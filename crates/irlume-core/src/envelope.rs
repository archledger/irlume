//! On-disk TPM envelope format for a sealed secret.
//!
//! ```json
//! {
//!   "version": 1,
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
        fs::write(path, s).map_err(|e| Error::Io(e.to_string()))?;
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        Ok(())
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
}
