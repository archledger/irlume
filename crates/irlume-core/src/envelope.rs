// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! On-disk TPM envelope format for a sealed secret.
//!
//! ```json
//! {
//!   "version": 1,
//!   "policy": { "kind": "PcrLiteral" },
//!   "pcrs": [7],
//!   "public":  "<base64 TPM2B_PUBLIC>",
//!   "private": "<base64 TPM2B_PRIVATE>",
//!   "pcr_values": [{ "pcr": 7, "value": "<base64 sha256>" }]
//! }
//! ```
//!
//! The sealed object's `authPolicy` is a literal `PolicyPCR` digest over `pcrs`
//! (here PCR 7, the UEFI Secure Boot state). The TPM rejects unseal the moment
//! any bound PCR drifts. `pcr_values` is diagnostics only; the TPM itself
//! enforces policy via the digest baked into `public`.

use base64::{engine::general_purpose::STANDARD, Engine};
use irlume_common::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Current envelope schema version for newly written envelopes.
pub const CURRENT_VERSION: u32 = 1;

/// How the sealed object's `authPolicy` is satisfied at unseal time. Older
/// envelopes have no `policy` field and default to [`PolicyKind::PcrLiteral`],
/// so they keep loading unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum PolicyKind {
    /// Tier 3 (universal): a literal `PolicyPCR` digest over `pcrs`. Breaks on
    /// any bound-PCR drift; the user re-runs `keyring arm` to rebind.
    #[default]
    PcrLiteral,
    /// Tier 1 (UKI/systemd-boot): `PolicyAuthorize` over a signing public key.
    /// Any PCR state for which a valid systemd-issued signature exists unseals,
    /// so kernel updates don't require a reseal.
    Authorized {
        pubkey_pem: String,
        #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
        policy_ref: Vec<u8>,
    },
    /// Tier 2 (GRUB2 + systemd-pcrlock): `PolicyAuthorizeNV` against a pcrlock
    /// NV index that holds the currently-valid PCR policy. `make-policy`
    /// re-predicts the index across Secure Boot / firmware updates, so PCR 7 /
    /// dbx changes don't require a reseal.
    PcrlockNv { nv_index: u32 },
}

impl PolicyKind {
    /// Strength rank of this tier, higher is stronger: signed PolicyAuthorize
    /// (Tier 1) > pcrlock NV (Tier 2) > literal PolicyPCR (Tier 3). Used to
    /// decide whether a re-seal would upgrade an existing envelope. The enum
    /// declaration order does not match tier order, so rank explicitly.
    pub fn strength_rank(&self) -> u8 {
        match self {
            PolicyKind::Authorized { .. } => 3,
            PolicyKind::PcrlockNv { .. } => 2,
            PolicyKind::PcrLiteral => 1,
        }
    }

    /// Human-readable tier label, shared by `irlume diag`, `status`, and the
    /// TUI so every surface names the tiers the same way.
    pub fn describe(&self) -> String {
        match self {
            PolicyKind::PcrLiteral => "literal PolicyPCR (Tier 3)".to_string(),
            PolicyKind::Authorized { .. } => "signed PolicyAuthorize (Tier 1)".to_string(),
            PolicyKind::PcrlockNv { nv_index } => format!("pcrlock NV 0x{nv_index:x} (Tier 2)"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValue {
    pub pcr: u32,
    #[serde(with = "b64")]
    pub value: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SealedEnvelope {
    pub version: u32,
    /// How the object's policy is satisfied. Absent in v1 literal envelopes →
    /// defaults to [`PolicyKind::PcrLiteral`].
    #[serde(default)]
    pub policy: PolicyKind,
    /// PCRs replayed via `PolicyPCR` at unseal time.
    pub pcrs: Vec<u32>,
    #[serde(with = "b64")]
    pub public: Vec<u8>,
    #[serde(with = "b64")]
    pub private: Vec<u8>,
    /// SHA-256 values for `pcrs`, same order, captured at seal time (diagnostics).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pcr_values: Vec<PcrValue>,
}

impl SealedEnvelope {
    pub fn load(path: &Path) -> Result<Self> {
        let s = fs::read_to_string(path).map_err(|e| Error::Io(e.to_string()))?;
        serde_json::from_str(&s).map_err(|e| Error::Protocol(e.to_string()))
    }

    /// Write the envelope as a root-only (0600) file: it contains the wrapped
    /// secret blob; only the TPM can unseal it, but keep it unreadable anyway.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::Io(e.to_string()))?;
        }
        let s = serde_json::to_string_pretty(self).map_err(|e| Error::Protocol(e.to_string()))?;
        irlume_common::write_0600(path, s.as_bytes()).map_err(|e| Error::Io(e.to_string()))
    }
}

mod b64 {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        use serde::Deserialize;
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strength_rank_orders_signed_above_pcrlock_above_literal() {
        let signed = PolicyKind::Authorized {
            pubkey_pem: String::new(),
            policy_ref: Vec::new(),
        };
        let pcrlock = PolicyKind::PcrlockNv { nv_index: 1 };
        let literal = PolicyKind::PcrLiteral;
        assert!(signed.strength_rank() > pcrlock.strength_rank());
        assert!(pcrlock.strength_rank() > literal.strength_rank());
        // A re-seal must never "upgrade" from a stronger tier to a weaker one.
        assert_eq!(signed.strength_rank(), 3);
        assert_eq!(literal.strength_rank(), 1);
    }

    #[test]
    fn envelope_roundtrips_through_json() {
        let env = SealedEnvelope {
            version: CURRENT_VERSION,
            policy: PolicyKind::PcrLiteral,
            pcrs: vec![7],
            public: vec![1, 2, 3],
            private: vec![4, 5, 6],
            pcr_values: vec![PcrValue {
                pcr: 7,
                value: vec![0xab; 32],
            }],
        };
        let s = serde_json::to_string(&env).unwrap();
        let back: SealedEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back.pcrs, env.pcrs);
        assert_eq!(back.policy, PolicyKind::PcrLiteral);
        assert_eq!(back.public, env.public);
        assert_eq!(back.private, env.private);
        assert_eq!(back.version, CURRENT_VERSION);
    }

    #[test]
    fn legacy_envelope_without_policy_defaults_to_literal() {
        // A v1 envelope written before the `policy` field existed must still
        // load and be treated as a literal-PCR seal.
        let json = r#"{"version":1,"pcrs":[7],"public":"AQID","private":"BAUG"}"#;
        let env: SealedEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(env.policy, PolicyKind::PcrLiteral);
        assert_eq!(env.pcrs, vec![7]);
    }

    #[test]
    fn describe_names_each_tier() {
        assert_eq!(
            PolicyKind::PcrLiteral.describe(),
            "literal PolicyPCR (Tier 3)"
        );
        assert_eq!(
            PolicyKind::Authorized {
                pubkey_pem: "PEM".into(),
                policy_ref: vec![0xde, 0xad],
            }
            .describe(),
            "signed PolicyAuthorize (Tier 1)"
        );
        assert_eq!(
            PolicyKind::PcrlockNv {
                nv_index: 0x1c00002
            }
            .describe(),
            "pcrlock NV 0x1c00002 (Tier 2)"
        );
    }

    #[test]
    fn authorized_variant_serde_roundtrips_and_skips_empty_policy_ref() {
        // Non-empty policy_ref is base64-encoded and survives a round-trip.
        let env = SealedEnvelope {
            version: CURRENT_VERSION,
            policy: PolicyKind::Authorized {
                pubkey_pem: "PEM-BODY".into(),
                policy_ref: vec![0xde, 0xad, 0xbe, 0xef],
            },
            pcrs: vec![11],
            public: vec![1],
            private: vec![2],
            pcr_values: vec![],
        };
        let s = serde_json::to_string(&env).unwrap();
        assert!(s.contains(r#""kind":"Authorized""#), "{s}");
        let back: SealedEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back.policy, env.policy);

        // Empty policy_ref must be omitted from the JSON and default back to empty.
        let env2 = SealedEnvelope {
            version: CURRENT_VERSION,
            policy: PolicyKind::Authorized {
                pubkey_pem: "P".into(),
                policy_ref: vec![],
            },
            pcrs: vec![11],
            public: vec![1],
            private: vec![2],
            pcr_values: vec![],
        };
        let s2 = serde_json::to_string(&env2).unwrap();
        assert!(!s2.contains("policy_ref"), "{s2}");
        let back2: SealedEnvelope = serde_json::from_str(&s2).unwrap();
        match back2.policy {
            PolicyKind::Authorized { policy_ref, .. } => assert!(policy_ref.is_empty()),
            other => panic!("expected Authorized, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_invalid_base64_field() {
        // The b64 field deserializer must surface a decode error rather than
        // yielding garbage bytes.
        let bad = r#"{"version":1,"pcrs":[7],"public":"@@@","private":"BAUG"}"#;
        assert!(serde_json::from_str::<SealedEnvelope>(bad).is_err());
    }

    #[test]
    fn save_then_load_roundtrips_on_disk_with_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("irlume-env-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Nested path forces save() to create the missing parent directory.
        let p = dir.join("sub/sealed.json");
        let env = SealedEnvelope {
            version: CURRENT_VERSION,
            policy: PolicyKind::PcrlockNv {
                nv_index: 0x1c00002,
            },
            pcrs: vec![7, 11],
            public: vec![9, 8, 7],
            private: vec![0],
            pcr_values: vec![PcrValue {
                pcr: 7,
                value: vec![0x11; 32],
            }],
        };
        env.save(&p).unwrap();

        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "envelope must be root-only");

        let back = SealedEnvelope::load(&p).unwrap();
        assert_eq!(back.version, CURRENT_VERSION);
        assert_eq!(back.pcrs, vec![7, 11]);
        assert_eq!(back.public, vec![9, 8, 7]);
        assert_eq!(
            back.policy,
            PolicyKind::PcrlockNv {
                nv_index: 0x1c00002
            }
        );
        assert_eq!(back.pcr_values.len(), 1);
        assert_eq!(back.pcr_values[0].value, vec![0x11; 32]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_errors_on_missing_and_malformed_file() {
        let dir = std::env::temp_dir().join(format!("irlume-env-err-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let missing = dir.join("nope.json");
        assert!(matches!(SealedEnvelope::load(&missing), Err(Error::Io(_))));

        let bad = dir.join("bad.json");
        std::fs::write(&bad, "{ not json").unwrap();
        assert!(matches!(
            SealedEnvelope::load(&bad),
            Err(Error::Protocol(_))
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
