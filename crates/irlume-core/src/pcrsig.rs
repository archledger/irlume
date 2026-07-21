// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Consume systemd's signed-PCR-policy artifacts (the Tier-1 / UKI path).
//!
//! When a Unified Kernel Image is built with `ukify --pcr-private-key` /
//! `--pcr-public-key` (or `systemd-measure sign`), systemd-stub exposes, at
//! boot:
//!   * `/run/systemd/tpm2-pcr-signature.json`: per-PCR-state signatures
//!   * `/run/systemd/tpm2-pcr-public-key.pem`: the authorizing public key
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

/// True when both signed-policy artifacts are present, i.e. the signed-PCR
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
    // The byte-indexed slicing below (`&s[i..i + 2]`) is only safe on ASCII:
    // a multibyte UTF-8 character would let `s.len()` pass the even-length
    // check yet make the slice split a char boundary and panic. Hex digits are
    // ASCII by definition, so reject anything else first. A tampered `.pcrsig`
    // that put a multibyte char in a hex field used to crash the daemon here.
    if !s.is_ascii() {
        return Err(Error::Protocol("non-hex characters in hex string".into()));
    }
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

    #[test]
    fn multibyte_char_in_hex_field_errors_not_panics() {
        // A `pol` of even BYTE length but containing a 2-byte UTF-8 char used to
        // panic in from_hex (byte-slicing across a char boundary). Found by the
        // pcr_signature fuzz target. It must return an error, not crash.
        let bad = "{\"sha256\":[{\"pcrs\":[7],\"pkfp\":\"7682\",\"pol\":\"2\u{01f0}bfca5\",\"sig\":\"\"}]}";
        assert!(parse_signatures(bad, "sha256").is_err());
    }

    #[test]
    fn rejects_bad_signature_base64() {
        // `sig` is base64-decoded; a non-base64 body must surface as a Protocol
        // error tagged so the operator can tell it apart from a bad `pol`.
        let bad = r#"{"sha256":[{"pcrs":[11],"pkfp":"7682","pol":"01","sig":"@@not-b64@@"}]}"#;
        match parse_signatures(bad, "sha256") {
            Err(Error::Protocol(m)) => assert!(m.contains("bad signature base64"), "{m}"),
            other => panic!("expected Protocol(bad signature base64), got {other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_json() {
        match parse_signatures("{ this is not json", "sha256") {
            Err(Error::Protocol(_)) => {}
            other => panic!("expected Protocol on bad JSON, got {other:?}"),
        }
    }

    #[test]
    fn rejects_entry_missing_required_field() {
        // `sig` omitted: serde fails the RawEntry decode -> Protocol.
        let bad = r#"{"sha256":[{"pcrs":[11],"pkfp":"aa","pol":"01"}]}"#;
        assert!(matches!(
            parse_signatures(bad, "sha256"),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn rejects_odd_length_hex_pol() {
        let bad = r#"{"sha256":[{"pcrs":[11],"pkfp":"aa","pol":"abc","sig":"AQ=="}]}"#;
        match parse_signatures(bad, "sha256") {
            Err(Error::Protocol(m)) => assert!(m.contains("odd-length"), "{m}"),
            other => panic!("expected Protocol(odd-length), got {other:?}"),
        }
    }

    #[test]
    fn parses_empty_pcrs_and_decodes_sig() {
        // Empty `pcrs` is structurally valid JSON and must parse; the base64
        // `sig` "AQ==" decodes to the single byte 0x01.
        let j = r#"{"sha256":[{"pcrs":[],"pkfp":"aa","pol":"02","sig":"AQ=="}]}"#;
        let sigs = parse_signatures(j, "sha256").unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].pcrs, Vec::<u32>::new());
        assert_eq!(sigs[0].pol, vec![0x02]);
        assert_eq!(sigs[0].sig, vec![0x01]);
    }

    // ---- filesystem/discovery paths (env-driven; serialized on ENV_LOCK) ----

    use std::sync::atomic::{AtomicU32, Ordering};
    static TMP_SEQ: AtomicU32 = AtomicU32::new(0);

    fn unique_tmp(name: &str) -> PathBuf {
        let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "irlume-pcrsig-test-{}-{}-{}",
            std::process::id(),
            n,
            name
        ))
    }

    fn clear_pcr_env() {
        std::env::remove_var("IRLUME_PCR_SIGNATURE");
        std::env::remove_var("IRLUME_PCR_PUBKEY");
    }

    #[test]
    fn discover_signature_path_env_override() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        clear_pcr_env();
        let p = unique_tmp("sig.json");
        std::fs::write(&p, FIXTURE).unwrap();
        std::env::set_var("IRLUME_PCR_SIGNATURE", &p);
        assert_eq!(discover_signature_path(), Some(p.clone()));

        // Env pointing at a nonexistent file yields None (not the stale path).
        std::env::set_var("IRLUME_PCR_SIGNATURE", "/nonexistent/irlume/none.json");
        assert_eq!(discover_signature_path(), None);

        // With the override gone, discovery walks the system dirs. Whatever it
        // returns (if anything) must be a real, correctly-named path.
        std::env::remove_var("IRLUME_PCR_SIGNATURE");
        if let Some(found) = discover_signature_path() {
            assert!(found.exists(), "discover must only return existing paths");
            assert!(found.ends_with(SIGNATURE_FILE));
        }
        clear_pcr_env();
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn discover_pubkey_path_env_override() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        clear_pcr_env();
        let p = unique_tmp("pub.pem");
        std::fs::write(&p, "PEM").unwrap();
        std::env::set_var("IRLUME_PCR_PUBKEY", &p);
        assert_eq!(discover_pubkey_path(), Some(p.clone()));

        std::env::set_var("IRLUME_PCR_PUBKEY", "/nonexistent/irlume/none.pem");
        assert_eq!(discover_pubkey_path(), None);

        std::env::remove_var("IRLUME_PCR_PUBKEY");
        if let Some(found) = discover_pubkey_path() {
            assert!(found.exists());
            assert!(found.ends_with(PUBKEY_FILE));
        }
        clear_pcr_env();
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn signed_policy_available_needs_both_artifacts() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        clear_pcr_env();
        let sig = unique_tmp("sig2.json");
        let pk = unique_tmp("pub2.pem");
        std::fs::write(&sig, FIXTURE).unwrap();
        std::fs::write(&pk, "PEM").unwrap();

        std::env::set_var("IRLUME_PCR_SIGNATURE", &sig);
        std::env::set_var("IRLUME_PCR_PUBKEY", &pk);
        assert!(signed_policy_available());

        // Missing the pubkey -> unavailable.
        std::env::set_var("IRLUME_PCR_PUBKEY", "/nonexistent/irlume/none.pem");
        assert!(!signed_policy_available());

        clear_pcr_env();
        let _ = std::fs::remove_file(&sig);
        let _ = std::fs::remove_file(&pk);
    }

    #[test]
    fn load_pubkey_pem_reads_file_or_errors() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        clear_pcr_env();
        let pk = unique_tmp("pub3.pem");
        let body = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n";
        std::fs::write(&pk, body).unwrap();
        std::env::set_var("IRLUME_PCR_PUBKEY", &pk);
        assert_eq!(load_pubkey_pem().unwrap(), body);

        // No discoverable key -> Policy error, not a panic.
        std::env::set_var("IRLUME_PCR_PUBKEY", "/nonexistent/irlume/none.pem");
        assert!(matches!(load_pubkey_pem(), Err(Error::Policy(_))));

        clear_pcr_env();
        let _ = std::fs::remove_file(&pk);
    }

    #[test]
    fn load_signatures_and_signed_pcrs_via_file() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        clear_pcr_env();
        let sig = unique_tmp("sig4.json");
        std::fs::write(&sig, FIXTURE).unwrap();
        std::env::set_var("IRLUME_PCR_SIGNATURE", &sig);

        let sigs = load_signatures("sha256").unwrap();
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].pkfp, "7682");

        assert_eq!(signed_pcrs("sha256"), Some(vec![11]));
        // A bank with no entries -> first() is None.
        assert_eq!(signed_pcrs("sha384"), None);

        // No signature file discoverable -> Policy error from load_signatures.
        std::env::set_var("IRLUME_PCR_SIGNATURE", "/nonexistent/irlume/none.json");
        assert!(matches!(load_signatures("sha256"), Err(Error::Policy(_))));
        assert_eq!(signed_pcrs("sha256"), None);

        clear_pcr_env();
        let _ = std::fs::remove_file(&sig);
    }
}
