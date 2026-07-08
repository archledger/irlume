//! Consume systemd's signed-PCR-policy artifacts (the Tier-1 / UKI path).
//!
//! When a Unified Kernel Image is built with `ukify --pcr-private-key` /
//! `--pcr-public-key` (or `systemd-measure sign`), systemd-stub exposes, at
//! boot:
//!   * `/run/systemd/tpm2-pcr-signature.json` — per-PCR-state signatures
//!   * `/run/systemd/tpm2-pcr-public-key.pem` — the authorizing public key
//!
//! Each kernel update reships a fresh signature inside the new UKI, so a
//! `PolicyAuthorize`-bound secret keeps unsealing across updates with no reseal
//! or re-enrollment. This module discovers and parses those files; the TPM
//! `PolicyAuthorize` machinery lives in [`crate::tpm`].
//!
//! This is the path that applies on systemd-boot / UKI distros (Arch, and any
//! Fedora/Pop install using a signed UKI). On a GRUB2 box with no signed UKI the
//! artifacts are absent, [`signed_policy_available`] is false, and the caller
//! falls back to the pcrlock (Tier 2) or literal-PCR (Tier 3) path.
//!
//! Signature-file schema (one array per PCR bank):
//! ```json
//! { "sha256": [ { "pcrs": [11], "pkfp": "<hex>", "pol": "<hex>", "sig": "<b64>" } ] }
//! ```
//! `pol` is the authorized PCR-policy digest; `sig` is the signature over it.

use base64::{engine::general_purpose::STANDARD, Engine};
use irlume_common::{Error, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Default PCR bank we operate in. systemd writes `sha256` on modern systems.
pub const DEFAULT_BANK: &str = "sha256";

/// Search order matching `systemd-cryptenroll`/`systemd-cryptsetup`.
const SEARCH_DIRS: [&str; 3] = ["/etc/systemd", "/run/systemd", "/usr/lib/systemd"];
const SIGNATURE_FILE: &str = "tpm2-pcr-signature.json";
const PUBKEY_FILE: &str = "tpm2-pcr-public-key.pem";

/// One authorized PCR policy + its signature, for a single PCR-state/phase.
#[derive(Debug, Clone)]
pub struct PcrSignature {
    /// PCR indices this signature covers (e.g. `[11]`).
    pub pcrs: Vec<u32>,
    /// Public-key fingerprint (hex), identifies the signing key.
    pub pkfp: String,
    /// The authorized PCR-policy digest (raw bytes).
    pub pol: Vec<u8>,
    /// Signature over the authorized policy (raw bytes).
    pub sig: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct RawEntry {
    pcrs: Vec<u32>,
    pkfp: String,
    pol: String,
    sig: String,
}

/// Locate the signature JSON, honouring `IRLUME_PCR_SIGNATURE` for test/dev.
pub fn discover_signature_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("IRLUME_PCR_SIGNATURE") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    discover(SIGNATURE_FILE)
}

/// Locate the public-key PEM, honouring `IRLUME_PCR_PUBKEY` for test/dev.
pub fn discover_pubkey_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("IRLUME_PCR_PUBKEY") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    discover(PUBKEY_FILE)
}

fn discover(file: &str) -> Option<PathBuf> {
    SEARCH_DIRS
        .iter()
        .map(|d| Path::new(d).join(file))
        .find(|p| p.exists())
}

/// True when both signed-policy artifacts are present — i.e. the signed-PCR
/// policy path is usable on this machine.
pub fn signed_policy_available() -> bool {
    discover_signature_path().is_some() && discover_pubkey_path().is_some()
}

/// Read the authorizing public key as PEM text.
pub fn load_pubkey_pem() -> Result<String> {
    let path = discover_pubkey_path()
        .ok_or_else(|| Error::Policy("no TPM2 PCR public key found".into()))?;
    std::fs::read_to_string(&path).map_err(|e| Error::Io(e.to_string()))
}

/// Parse all signatures for `bank` from the discovered signature file.
pub fn load_signatures(bank: &str) -> Result<Vec<PcrSignature>> {
    let path = discover_signature_path()
        .ok_or_else(|| Error::Policy("no TPM2 PCR signature file found".into()))?;
    let text = std::fs::read_to_string(&path).map_err(|e| Error::Io(e.to_string()))?;
    parse_signatures(&text, bank)
}

/// Parse signatures for `bank` from in-memory JSON (the testable core of
/// [`load_signatures`]).
pub fn parse_signatures(text: &str, bank: &str) -> Result<Vec<PcrSignature>> {
    let raw: HashMap<String, Vec<RawEntry>> =
        serde_json::from_str(text).map_err(|e| Error::Protocol(e.to_string()))?;
    let entries = match raw.get(bank) {
        Some(e) => e,
        None => return Ok(Vec::new()),
    };
    entries
        .iter()
        .map(|e| {
            Ok(PcrSignature {
                pcrs: e.pcrs.clone(),
                pkfp: e.pkfp.clone(),
                pol: from_hex(&e.pol)?,
                sig: STANDARD
                    .decode(&e.sig)
                    .map_err(|err| Error::Protocol(format!("bad signature base64: {err}")))?,
            })
        })
        .collect()
}

/// Find a signature whose authorized policy digest equals `policy_digest`
/// (and that covers exactly `pcrs`). Returns the first match.
pub fn find_for_policy<'a>(
    sigs: &'a [PcrSignature],
    pcrs: &[u32],
    policy_digest: &[u8],
) -> Option<&'a PcrSignature> {
    sigs.iter()
        .find(|s| s.pol == policy_digest && s.pcrs == pcrs)
}

/// The PCR set covered by the discovered signatures (e.g. `[11]`). Used to seal
/// against exactly the PCRs systemd signs, rather than guessing. Returns the
/// first entry's `pcrs` for the requested bank; `None` if no signatures.
pub fn signed_pcrs(bank: &str) -> Option<Vec<u32>> {
    load_signatures(bank).ok()?.first().map(|s| s.pcrs.clone())
}

fn from_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(Error::Protocol("odd-length hex string".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| Error::Protocol(format!("bad hex: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"{
      "sha1": [
        {"pcrs":[11],"pkfp":"aa","pol":"0102","sig":"AAEC"}
      ],
      "sha256": [
        {"pcrs":[11],"pkfp":"7682","pol":"265bfca5","sig":"anN2"},
        {"pcrs":[11],"pkfp":"7682","pol":"deadbeef","sig":"Y2Fm"}
      ]
    }"#;

    #[test]
    fn parses_requested_bank_only() {
        let sha256 = parse_signatures(FIXTURE, "sha256").unwrap();
        assert_eq!(sha256.len(), 2);
        assert_eq!(sha256[0].pcrs, vec![11]);
        assert_eq!(sha256[0].pol, vec![0x26, 0x5b, 0xfc, 0xa5]);
    }

    #[test]
    fn missing_bank_is_empty_not_error() {
        assert!(parse_signatures(FIXTURE, "sha384").unwrap().is_empty());
    }

    #[test]
    fn find_matches_policy_and_pcrs() {
        let sigs = parse_signatures(FIXTURE, "sha256").unwrap();
        assert!(find_for_policy(&sigs, &[11], &[0xde, 0xad, 0xbe, 0xef]).is_some());
        assert!(find_for_policy(&sigs, &[7, 11], &[0xde, 0xad, 0xbe, 0xef]).is_none());
        assert!(find_for_policy(&sigs, &[11], &[0x00]).is_none());
    }

    #[test]
    fn rejects_bad_hex() {
        let bad = r#"{"sha256":[{"pcrs":[11],"pkfp":"a","pol":"xyz","sig":"AA=="}]}"#;
        assert!(parse_signatures(bad, "sha256").is_err());
    }
}
