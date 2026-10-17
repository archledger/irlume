// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The `tpm-endorsement` doctor check (ADR-0036): what irlumed's root-only
//! `TpmEndorsement` request reports about the TPM's endorsement key (EK)
//! certificates, in doctor's words. The CLI never opens the TPM.
//!
//! Every string in the report that came from a certificate (a CA's name,
//! the TPM model and version, and the details that quote them) is untrusted:
//! it reaches the terminal, `--json` and the TUI as visible ASCII on one
//! bounded line (ADR-0036 section 7). The report holds no EK public key,
//! hash, serial or fingerprint, so none can reach doctor's output.

use crate::doctor_report::State;
use irlume_common::tpm_endorsement::{
    EndorsementCertificate, EndorsementReport, EndorsementState, SkippedKind, CLIENT_BUDGET,
};
use irlume_common::{Request, Response};

/// The longest text taken from one certificate field, and from one detail
/// irlumed wrote about a certificate.
const MAX_FIELD: usize = 64;
const MAX_DETAIL: usize = 320;

/// Ask irlumed through the socket, within the request's own budget.
pub(crate) fn from_irlumed() -> Result<EndorsementReport, String> {
    ask(|request| irlume_common::client::request_with_timeout(request, CLIENT_BUDGET))
}

/// Ask irlumed for the check. Every way of getting no report (an older
/// daemon, an absent one, a refusal, an unreadable reply) is the reason.
pub(crate) fn ask(
    ask: impl FnOnce(&Request) -> std::io::Result<Response>,
) -> Result<EndorsementReport, String> {
    match ask(&Request::TpmEndorsement) {
        Ok(Response::TpmEndorsement(report)) => Ok(report),
        Ok(Response::Error(error)) if error == "bad request" => {
            Err("irlumed predates the endorsement check".to_owned())
        }
        Ok(Response::Error(error)) => Err(format!("irlumed: {}", visible(&error, MAX_DETAIL))),
        Err(error) if irlume_common::client::proves_daemon_absent(&error) => {
            Err("irlumed is not running".to_owned())
        }
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Err(format!(
            "irlumed did not answer within {} seconds",
            CLIENT_BUDGET.as_secs()
        )),
        Err(error) => Err(format!("irlumed's reply could not be read: {error}")),
        Ok(_) => Err("irlumed returned an unexpected reply".to_owned()),
    }
}

/// The `tpm-endorsement` check from irlumed's report, as of `now` (unix
/// seconds), against which a CA's end date is reported as passed.
pub(crate) fn check(report: &Result<EndorsementReport, String>, now: u64) -> (State, String) {
    let report = match report {
        Ok(report) => report,
        Err(reason) => {
            return (
                State::Unknown,
                format!("EK certificates not read: {reason}"),
            )
        }
    };
    let state = match report.state {
        EndorsementState::Pass => State::Pass,
        EndorsementState::Warn => State::Warn,
        EndorsementState::Info => State::Info,
        EndorsementState::Unknown => State::Unknown,
    };
    let mut parts: Vec<String> = Vec::new();
    if report.certificates.is_empty() {
        parts.push(match (&report.stopped, report.state) {
            (Some(why), _) => format!("not judged: {}", visible(why, MAX_DETAIL)),
            (None, EndorsementState::Info) if report.skipped.is_empty() => {
                "the TPM stores no EK certificate, and irlume does not fetch one".to_owned()
            }
            (None, EndorsementState::Info) => "the TPM stores no certificate for an EK irlume \
                                               can test, and irlume does not fetch one"
                .to_owned(),
            (None, _) => "no EK certificate was judged".to_owned(),
        });
    } else {
        parts.extend(report.certificates.iter().map(|c| certificate(c, now)));
        if let Some(why) = &report.stopped {
            parts.push(format!("stopped: {}", visible(why, MAX_DETAIL)));
        }
    }
    if !report.not_judged.is_empty() {
        parts.push(format!(
            "not judged, beyond the four irlume checks: {}",
            indices(report.not_judged.iter().copied())
        ));
    }
    if !report.skipped.is_empty() {
        let skipped: Vec<String> = report
            .skipped
            .iter()
            .map(|s| format!("{:#010X} ({})", s.index, skipped_kind(s.kind)))
            .collect();
        parts.push(format!(
            "skipped, for EKs irlume cannot test: {}",
            skipped.join(", ")
        ));
    }
    (state, parts.join("; "))
}

/// One certificate: its index, its EK's algorithm, its state and why, and
/// when its chain verified, the TPM it names and any CA whose validity
/// ended (reported, not enforced).
fn certificate(c: &EndorsementCertificate, now: u64) -> String {
    let state = match c.state {
        EndorsementState::Pass => "pass",
        EndorsementState::Warn => "warn",
        EndorsementState::Info => "info",
        EndorsementState::Unknown => "unknown",
    };
    let mut text = format!(
        "{} EK certificate at {:#010X}: {state}: {}",
        visible(&c.key, MAX_FIELD),
        c.index,
        visible(&c.detail, MAX_DETAIL)
    );
    if let Some(tpm) = &c.tpm {
        text.push_str(&format!(
            " (TPM {} {}, firmware {} when certified)",
            vendor_text(tpm.manufacturer),
            visible(&tpm.model, MAX_FIELD),
            visible(&tpm.version, MAX_FIELD)
        ));
    }
    let ended: Vec<String> = c
        .chain
        .iter()
        .filter(|ca| ca.not_after < now)
        .map(|ca| {
            format!(
                "{} ended {}",
                visible(&ca.name, MAX_FIELD),
                date(ca.not_after)
            )
        })
        .collect();
    if !ended.is_empty() {
        text.push_str(&format!(
            " (CA validity, reported and not enforced: {})",
            ended.join(", ")
        ));
    }
    text
}

fn skipped_kind(kind: SkippedKind) -> &'static str {
    match kind {
        SkippedKind::Signing => "a signing EK",
        SkippedKind::FirmwareLimited => "a firmware-limited EK",
        SkippedKind::MlKem => "an ML-KEM EK",
        SkippedKind::Sm2 => "the SM2 EK",
        SkippedKind::Unknown => "an EK this irlume does not know",
    }
}

fn indices(indices: impl Iterator<Item = u32>) -> String {
    indices
        .map(|i| format!("{i:#010X}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A TCG vendor ID (`TPM_PT_MANUFACTURER`) as its four ASCII characters,
/// such as "STM" or "IFX".
fn vendor_text(id: u32) -> String {
    let text: String = id
        .to_be_bytes()
        .iter()
        .map(|b| {
            if b.is_ascii_graphic() || *b == b' ' {
                char::from(*b)
            } else {
                '?'
            }
        })
        .collect();
    text.trim().to_owned()
}

/// A unix time as its UTC calendar date, such as "2025-10-20".
fn date(at: u64) -> String {
    let (year, month, day) = crate::tui::dates::civil_date(at, 0);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Untrusted text as visible ASCII on one line of at most `max` characters:
/// anything else shows as `?`, and a longer text ends in `...`.
fn visible(text: &str, max: usize) -> String {
    let mut out: String = text
        .chars()
        .take(max)
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect();
    if text.chars().count() > max {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use irlume_common::tpm_endorsement::{CertificateAuthority, CertifiedTpm, SkippedCertificate};

    fn report(state: EndorsementState) -> EndorsementReport {
        EndorsementReport {
            state,
            stopped: None,
            certificates: Vec::new(),
            skipped: Vec::new(),
            not_judged: Vec::new(),
        }
    }

    fn certificate(state: EndorsementState, detail: &str) -> EndorsementCertificate {
        EndorsementCertificate {
            index: 0x01C0_0002,
            key: "RSA 2048".into(),
            state,
            detail: detail.into(),
            tpm: None,
            chain: Vec::new(),
        }
    }

    const NOW: u64 = 1_792_000_000; // 2026-10-14

    /// Each way of getting no report is unknown with its reason, and the
    /// request asked is the endorsement check's.
    #[test]
    fn the_report_comes_only_from_irlumed() {
        let reason = |reply: std::io::Result<Response>| {
            ask(|request| {
                assert!(matches!(request, Request::TpmEndorsement));
                reply
            })
            .unwrap_err()
        };
        assert!(reason(Ok(Response::Error("bad request".into())))
            .contains("predates the endorsement check"));
        assert!(reason(Err(std::io::ErrorKind::NotFound.into())).contains("not running"));
        assert!(reason(Err(std::io::ErrorKind::TimedOut.into())).contains("within 60 seconds"));
        assert!(reason(Err(std::io::ErrorKind::InvalidData.into())).contains("could not be read"));
        assert!(reason(Ok(Response::Error(
            "TPM endorsement requires root (peer uid 1000)".into()
        )))
        .contains("requires root"));
        assert!(reason(Ok(Response::Pong)).contains("unexpected"));
        let (state, detail) = check(
            &Err("irlumed: TPM endorsement requires root (peer uid 1000)".into()),
            NOW,
        );
        assert_eq!(state, State::Unknown);
        assert!(detail.contains("requires root"), "{detail}");

        let passed = ask(|_| Ok(Response::TpmEndorsement(report(EndorsementState::Info))));
        assert_eq!(passed, Ok(report(EndorsementState::Info)));
    }

    #[test]
    fn a_tpm_without_certificates_is_info_and_a_stopped_check_says_why() {
        let (state, detail) = check(&Ok(report(EndorsementState::Info)), NOW);
        assert_eq!(state, State::Info);
        assert!(detail.contains("stores no EK certificate"), "{detail}");
        assert!(detail.contains("does not fetch"), "{detail}");

        // Only certificates for EKs irlume cannot test: still info, said so.
        let only_skipped = EndorsementReport {
            skipped: vec![SkippedCertificate {
                index: 0x01C0_0032,
                kind: SkippedKind::Signing,
            }],
            ..report(EndorsementState::Info)
        };
        let (state, detail) = check(&Ok(only_skipped), NOW);
        assert_eq!(state, State::Info);
        assert!(
            detail.contains("no certificate for an EK irlume can test"),
            "{detail}"
        );
        assert!(!detail.contains("stores no EK certificate"), "{detail}");
        assert!(detail.contains("0x01C00032 (a signing EK)"), "{detail}");

        let stopped = EndorsementReport::stopped(
            "the endorsement hierarchy's authorization is set, so irlume does not use the EK",
        );
        let (state, detail) = check(&Ok(stopped), NOW);
        assert_eq!(state, State::Unknown);
        assert!(
            detail.starts_with("not judged: the endorsement"),
            "{detail}"
        );
    }

    /// A pass names the TPM the certificate names and its result; the
    /// worst-first state comes from irlumed; every certificate, skipped and
    /// unjudged index is named.
    #[test]
    fn every_certificate_is_named_with_its_result() {
        let mut pass = certificate(
            EndorsementState::Pass,
            "verifies to CN=Test Root, matches the TPM's endorsement key, and irlume's storage \
             key is in the same TPM",
        );
        pass.tpm = Some(CertifiedTpm {
            manufacturer: 0x5354_4D20,
            model: "ST33HTPHAHE4".into(),
            version: "id:00090108".into(),
        });
        pass.chain = vec![
            CertificateAuthority {
                name: "CN=Expired Issuing CA".into(),
                not_after: 1_760_918_400, // 2025-10-20
            },
            CertificateAuthority {
                name: "CN=Test Root".into(),
                not_after: 2_082_672_000,
            },
        ];
        let mut warn = certificate(
            EndorsementState::Warn,
            "the certificate is not for this TPM's endorsement key",
        );
        warn.index = 0x01C0_000A;
        warn.key = "ECC NIST P-256".into();
        let report = EndorsementReport {
            state: EndorsementState::Warn,
            stopped: None,
            certificates: vec![pass, warn],
            skipped: vec![SkippedCertificate {
                index: 0x01C0_0032,
                kind: SkippedKind::Signing,
            }],
            not_judged: vec![0x01C0_001E],
        };
        let (state, detail) = check(&Ok(report), NOW);
        assert_eq!(state, State::Warn);
        for part in [
            "RSA 2048 EK certificate at 0x01C00002: pass: verifies to CN=Test Root",
            "(TPM STM ST33HTPHAHE4, firmware id:00090108 when certified)",
            "CN=Expired Issuing CA ended 2025-10-20",
            "ECC NIST P-256 EK certificate at 0x01C0000A: warn: the certificate is not for",
            "not judged, beyond the four irlume checks: 0x01C0001E",
            "skipped, for EKs irlume cannot test: 0x01C00032 (a signing EK)",
        ] {
            assert!(detail.contains(part), "{part} in {detail}");
        }
        assert!(
            !detail.contains("Test Root ended"),
            "a CA still valid is not listed: {detail}"
        );
    }

    /// ADR-0036 section 7: text from a certificate reaches doctor as visible
    /// ASCII on one bounded line.
    #[test]
    fn certificate_text_reaches_doctor_as_visible_ascii_on_one_bounded_line() {
        let hostile = "ST33\u{1b}[2J\u{7}\r\nINJECTED\u{202e}line";
        let mut c = certificate(EndorsementState::Pass, hostile);
        c.tpm = Some(CertifiedTpm {
            manufacturer: 0x0A1B_4D20,
            model: hostile.into(),
            version: "x".repeat(500),
        });
        c.chain = vec![CertificateAuthority {
            name: hostile.into(),
            not_after: 1,
        }];
        let report = EndorsementReport {
            certificates: vec![c],
            ..report(EndorsementState::Pass)
        };
        let (_, detail) = check(&Ok(report), NOW);
        assert!(
            detail.chars().all(|c| c.is_ascii_graphic() || c == ' '),
            "{detail:?}"
        );
        assert!(detail.contains("ST33?[2J???INJECTED?line"), "{detail}");
        assert!(detail.contains(&format!("{}...", "x".repeat(MAX_FIELD))));
        assert!(!detail.contains(&"x".repeat(MAX_FIELD + 1)));
        let (_, refused) = check(&ask(|_| Ok(Response::Error(hostile.into()))), NOW);
        assert!(
            refused.chars().all(|c| c.is_ascii_graphic() || c == ' '),
            "{refused:?}"
        );
    }
}
