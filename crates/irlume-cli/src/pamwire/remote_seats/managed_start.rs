// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Managed-start policy evidence for the LightDM restart gate.
//!
//! The timestamp rule in [`super::running_lightdm_predates_its_configuration`]
//! orders a wall-clock configuration change against a process start, so a
//! clock step can order them wrongly, and it reads `/proc`, so under `hidepid`
//! an unprivileged `login plan` sees nothing while a root `login apply` sees
//! the process and derives a different plan. The shared research record
//! (artifacts/irlume/2026-10-02-lightdm-restart-proof) proves no stateless
//! reader of timestamps and file metadata can close either gap: the missing
//! fact is the remote-server policy the running invocation actually loaded.
//!
//! This module is the consumer half of that contract. A qualified producer
//! (wrapper-owned exec path with an immutable configuration view, per the
//! contract in artifacts/irlume/2026-10-03-lightdm-managed-start) publishes a
//! receipt tied to one systemd invocation, and the verdict machine here
//! samples the manager, the receipt, and the manager again, accepting a
//! result only when both samples identify the same launch and the receipt
//! names exactly that launch. Identity is compared by equality within one
//! invocation, never by ordering wall times, so a clock step cannot forge or
//! erase a verdict, and the observation does not read `/proc`.
//!
//! Until the producer ships, every real source yields no receipt and the
//! verdict is `Unknown`; the timestamp rule keeps its current role. Nothing
//! here upgrades a missing record or an inactive unit into proof that no
//! remote-serving LightDM exists: `Absent` requires the source's explicit
//! qualified-absence authority, and root and unprivileged callers must feed
//! the same source the same facts.

// The restart gate reads `Running`; the qualified-absence authority and parts
// of the receipt are defined for producers that do not exist yet.
#![allow(dead_code)]

mod loader;
mod producer;
mod system;

use std::fmt;

/// The canonical unit this evidence is defined for.
pub(crate) const LIGHTDM_UNIT: &str = "lightdm.service";

/// Receipt schema understood by this reader.
const SCHEMA_VERSION: u32 = 1;

/// The remote-server policy one invocation actually loaded, published by the
/// producer after configuration load and bound to that invocation. No
/// configuration bytes, startup arguments, environment or secrets appear
/// here, per the receipt boundary of the contract.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    schema: u32,
    unit: String,
    /// Thirty-two lowercase hex characters: systemd's randomized per-start
    /// invocation identifier for the unit.
    invocation_id: String,
    /// The main process the manager attributes to the unit for that
    /// invocation. A wrapper that execs the daemon keeps one PID throughout.
    main_pid: u32,
    /// `ExecMainStartTimestampMonotonic` in microseconds, from the manager.
    exec_start_monotonic_us: u64,
    /// Sixty-four lowercase hex characters digesting the qualified executable
    /// and its execution contract.
    target_digest: String,
    /// Name of the immutable configuration generation the daemon loaded.
    config_generation: String,
    xdmcp_enabled: bool,
    vnc_enabled: bool,
    /// PAM generation and service roots protected for this invocation.
    pam_generation_roots: Vec<String>,
    /// Producer version, for migration and refusal decisions.
    producer_version: String,
}

impl Receipt {
    /// Parse and validate one receipt. Unknown fields, a future schema, a
    /// different unit, malformed hex or empty identity each refuse the whole
    /// record: a partially understood receipt proves nothing.
    pub(crate) fn from_json(text: &str) -> Result<Self, String> {
        let receipt: Self = serde_json::from_str(text).map_err(|e| format!("receipt: {e}"))?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != SCHEMA_VERSION {
            return Err(format!(
                "receipt schema {} is not {}",
                self.schema, SCHEMA_VERSION
            ));
        }
        if self.unit != LIGHTDM_UNIT {
            return Err(format!("receipt unit {} is not {LIGHTDM_UNIT}", self.unit));
        }
        if !is_lower_hex(&self.invocation_id, 32) {
            return Err("receipt invocation id is not 32 hex characters".into());
        }
        if !is_lower_hex(&self.target_digest, 64) {
            return Err("receipt target digest is not 64 hex characters".into());
        }
        if self.main_pid == 0 {
            return Err("receipt main pid is zero".into());
        }
        if self.exec_start_monotonic_us == 0 {
            return Err("receipt exec start monotonic is zero".into());
        }
        if self.config_generation.is_empty() {
            return Err("receipt config generation is empty".into());
        }
        if self.producer_version.is_empty() {
            return Err("receipt producer version is empty".into());
        }
        if self.pam_generation_roots.iter().any(String::is_empty) {
            return Err("receipt pam generation root is empty".into());
        }
        Ok(())
    }

    /// The receipt names exactly this observation's launch. Monotonic
    /// microseconds and the invocation id together identify one start of one
    /// process; comparing them for equality is what makes the check immune to
    /// clock steps.
    fn names(&self, observation: &ManagerObservation) -> bool {
        self.unit == observation.unit
            && self.invocation_id == observation.invocation_id
            && self.main_pid == observation.main_pid
            && self.exec_start_monotonic_us == observation.exec_start_monotonic_us
    }
}

/// One sample of the manager's own view of the unit. All fields are read-only
/// D-Bus properties generally available to every client, so an unprivileged
/// `login plan` and a root `login apply` observe the same facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagerObservation {
    pub(crate) unit: String,
    pub(crate) invocation_id: String,
    pub(crate) main_pid: u32,
    pub(crate) exec_start_monotonic_us: u64,
    pub(crate) active: bool,
}

/// Positive authority that no relevant consumer exists on this machine, which
/// only a qualified startup authority (closed set of LightDM start paths plus
/// the managed unit's absence) can supply. An inactive unit or a missing
/// receipt is not this proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AbsenceProof {
    pub(crate) unit: String,
}

/// Where the verdict machine's facts come from. The production source pairs
/// manager properties with the producer's receipt file; tests supply
/// synthetic facts. Both samples a source returns must describe reality at
/// the moment they are taken, which is what the before/after identity check
/// relies on.
pub(crate) trait Source {
    /// Sample the manager's view, or `None` when it cannot be observed.
    fn observe_manager(&self) -> Option<ManagerObservation>;
    /// Read and validate the producer's receipt, or `None` when none exists.
    fn read_receipt(&self) -> Option<Result<Receipt, String>>;
    /// Confirm the target process of this observation is alive right now.
    fn target_alive(&self, observation: &ManagerObservation) -> bool;
    /// Qualified-absence authority, if this source has one.
    fn absence_proof(&self) -> Option<AbsenceProof>;
}

/// The outcome of the managed-start observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// This invocation loaded its configuration with both remote servers off.
    VerifiedOff {
        invocation_id: String,
        config_generation: String,
    },
    /// This invocation loaded a configuration that turns a remote server on.
    RemoteOn {
        invocation_id: String,
        config_generation: String,
    },
    /// A qualified authority establishes no relevant consumer exists.
    Absent,
    /// Anything less certain: no producer, inactive or unobservable unit,
    /// mismatched or tampered evidence, or a launch that changed underneath
    /// the observation.
    Unknown(String),
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::VerifiedOff { .. } => write!(f, "verified-off"),
            Verdict::RemoteOn { .. } => write!(f, "remote-on"),
            Verdict::Absent => write!(f, "absent"),
            Verdict::Unknown(reason) => write!(f, "unknown: {reason}"),
        }
    }
}

/// Observe the running invocation and decide what its loaded policy proves.
///
/// The order is the contract's: sample the manager, read the receipt, confirm
/// the target's lifetime, then sample the manager again and require the same
/// launch in all three places. Root and unprivileged callers must pass a
/// source that answers both samples identically; a source whose privilege
/// changes its answers is not a valid source, and no privileged fallback may
/// turn another caller's `Unknown` into a positive result.
pub(crate) fn evaluate(source: &dyn Source) -> Verdict {
    let before = match source.observe_manager() {
        Some(observation) => observation,
        None => return Verdict::Unknown("manager observation unavailable".into()),
    };
    if !before.active {
        return match source.absence_proof() {
            Some(proof) if proof.unit == before.unit => Verdict::Absent,
            _ => Verdict::Unknown(format!("{} is inactive", before.unit)),
        };
    }
    if before.main_pid == 0 {
        return Verdict::Unknown("unit has no main process".into());
    }
    if before.invocation_id.len() != 32 || !is_lower_hex(&before.invocation_id, 32) {
        return Verdict::Unknown("manager invocation id is malformed".into());
    }
    let receipt = match source.read_receipt() {
        Some(Ok(receipt)) => receipt,
        Some(Err(reason)) => return Verdict::Unknown(reason),
        None => return Verdict::Unknown("no managed-start receipt".into()),
    };
    if !receipt.names(&before) {
        return Verdict::Unknown("receipt does not name the current invocation".into());
    }
    if !source.target_alive(&before) {
        return Verdict::Unknown("target lifetime unconfirmed".into());
    }
    let after = match source.observe_manager() {
        Some(observation) => observation,
        None => return Verdict::Unknown("second manager observation unavailable".into()),
    };
    if after.invocation_id != before.invocation_id
        || after.main_pid != before.main_pid
        || after.exec_start_monotonic_us != before.exec_start_monotonic_us
    {
        return Verdict::Unknown("invocation changed during the observation".into());
    }
    if !receipt.names(&after) {
        return Verdict::Unknown("receipt does not name the confirmed invocation".into());
    }
    let invocation_id = receipt.invocation_id;
    let config_generation = receipt.config_generation;
    if receipt.xdmcp_enabled || receipt.vnc_enabled {
        Verdict::RemoteOn {
            invocation_id,
            config_generation,
        }
    } else {
        Verdict::VerifiedOff {
            invocation_id,
            config_generation,
        }
    }
}

/// What the managed-start evidence establishes about the running LightDM,
/// for the restart gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Running {
    /// The running launch loaded the configuration named by `generation`;
    /// `remote` when that configuration turns a remote server on.
    Loaded { generation: String, remote: bool },
    /// No qualified evidence; the existing rule decides.
    Unknown(String),
}

/// Observe the running LightDM through the production source.
pub(super) fn running_lightdm() -> Running {
    running_from(&system::SystemSource::lightdm())
}

fn running_from(source: &dyn Source) -> Running {
    match evaluate(source) {
        Verdict::VerifiedOff {
            config_generation, ..
        } => Running::Loaded {
            generation: config_generation,
            remote: false,
        },
        Verdict::RemoteOn {
            config_generation, ..
        } => Running::Loaded {
            generation: config_generation,
            remote: true,
        },
        Verdict::Absent => Running::Unknown("absent".into()),
        Verdict::Unknown(reason) => Running::Unknown(reason),
    }
}

/// The digest of the configuration LightDM would load now. Every input must
/// be readable by anyone, so root and an unprivileged plan agree.
pub(super) fn current_generation() -> Result<String, String> {
    loader::observe(
        std::path::Path::new("/"),
        &loader::Profile::standard(),
        true,
    )
    .map(|seen| seen.digest)
}

/// The drop-in's producer commands.
pub(super) fn run_producer(action: &str, args: &[String]) -> std::process::ExitCode {
    producer::run(action, args)
}

fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn observation(invocation: &str) -> ManagerObservation {
        ManagerObservation {
            unit: LIGHTDM_UNIT.into(),
            invocation_id: invocation.into(),
            main_pid: 4211,
            exec_start_monotonic_us: 987_654_321,
            active: true,
        }
    }

    fn receipt_json(invocation: &str) -> String {
        format!(
            "{{\"schema\":1,\"unit\":\"lightdm.service\",\"invocation_id\":\"{invocation}\",\
             \"main_pid\":4211,\"exec_start_monotonic_us\":987654321,\
             \"target_digest\":\"{}\",\"config_generation\":\"g-7\",\
             \"xdmcp_enabled\":false,\"vnc_enabled\":false,\
             \"pam_generation_roots\":[\"/run/irlume-lightdm/pam.d\"],\
             \"producer_version\":\"0\"}}",
            "a".repeat(64)
        )
    }

    /// A source whose facts the test scripts. `second` is the observation the
    /// second sample returns; `receipt` is what the receipt read yields.
    struct Scripted {
        first: Option<ManagerObservation>,
        second: Option<ManagerObservation>,
        receipt: Option<Result<Receipt, String>>,
        alive: Cell<usize>,
        alive_limit: usize,
        absence: Option<AbsenceProof>,
    }

    impl Scripted {
        fn live(invocation: &str) -> Self {
            Scripted {
                first: Some(observation(invocation)),
                second: Some(observation(invocation)),
                receipt: Some(Ok(Receipt::from_json(&receipt_json(invocation)).unwrap())),
                alive: Cell::new(0),
                alive_limit: usize::MAX,
                absence: None,
            }
        }
    }

    impl Source for Scripted {
        fn observe_manager(&self) -> Option<ManagerObservation> {
            let sample = self.alive.get();
            if sample == 0 {
                self.first.clone()
            } else {
                self.second.clone()
            }
        }
        fn read_receipt(&self) -> Option<Result<Receipt, String>> {
            self.receipt.clone()
        }
        fn target_alive(&self, _observation: &ManagerObservation) -> bool {
            let sample = self.alive.get();
            self.alive.set(sample + 1);
            sample < self.alive_limit
        }
        fn absence_proof(&self) -> Option<AbsenceProof> {
            self.absence.clone()
        }
    }

    #[test]
    fn a_live_matching_receipt_with_both_servers_off_verifies_off() {
        let source = Scripted::live("b".repeat(32).as_str());
        assert_eq!(
            evaluate(&source),
            Verdict::VerifiedOff {
                invocation_id: "b".repeat(32),
                config_generation: "g-7".into()
            }
        );
    }

    #[test]
    fn a_receipt_that_turns_a_remote_server_on_reports_remote_on() {
        for (xdmcp, vnc) in [(true, false), (false, true), (true, true)] {
            let mut source = Scripted::live("b".repeat(32).as_str());
            let text = receipt_json(&"b".repeat(32))
                .replace(
                    "\"xdmcp_enabled\":false",
                    &format!("\"xdmcp_enabled\":{xdmcp}"),
                )
                .replace("\"vnc_enabled\":false", &format!("\"vnc_enabled\":{vnc}"));
            source.receipt = Some(Ok(Receipt::from_json(&text).unwrap()));
            assert_eq!(
                evaluate(&source),
                Verdict::RemoteOn {
                    invocation_id: "b".repeat(32),
                    config_generation: "g-7".into()
                }
            );
        }
    }

    #[test]
    fn a_missing_receipt_is_unknown_and_never_absent() {
        let mut source = Scripted::live("b".repeat(32).as_str());
        source.receipt = None;
        assert_eq!(
            evaluate(&source),
            Verdict::Unknown("no managed-start receipt".into())
        );
    }

    #[test]
    fn an_inactive_unit_without_absence_authority_stays_unknown() {
        let mut source = Scripted::live("b".repeat(32).as_str());
        let mut inactive = observation("b".repeat(32).as_str());
        inactive.active = false;
        source.first = Some(inactive.clone());
        source.second = Some(inactive);
        assert_eq!(
            evaluate(&source),
            Verdict::Unknown("lightdm.service is inactive".into())
        );
    }

    #[test]
    fn an_inactive_unit_with_qualified_absence_authority_is_absent() {
        let mut source = Scripted::live("b".repeat(32).as_str());
        let mut inactive = observation("b".repeat(32).as_str());
        inactive.active = false;
        source.first = Some(inactive.clone());
        source.second = Some(inactive);
        source.absence = Some(AbsenceProof {
            unit: LIGHTDM_UNIT.into(),
        });
        assert_eq!(evaluate(&source), Verdict::Absent);
    }

    #[test]
    fn an_active_unit_contradicts_absence_authority_and_stays_positive() {
        let mut source = Scripted::live("b".repeat(32).as_str());
        source.absence = Some(AbsenceProof {
            unit: LIGHTDM_UNIT.into(),
        });
        assert_eq!(
            evaluate(&source),
            Verdict::VerifiedOff {
                invocation_id: "b".repeat(32),
                config_generation: "g-7".into()
            }
        );
    }

    #[test]
    fn absence_authority_for_another_unit_does_not_apply() {
        let mut source = Scripted::live("b".repeat(32).as_str());
        let mut inactive = observation("b".repeat(32).as_str());
        inactive.active = false;
        source.first = Some(inactive.clone());
        source.second = Some(inactive);
        source.absence = Some(AbsenceProof {
            unit: "other.service".into(),
        });
        assert_eq!(
            evaluate(&source),
            Verdict::Unknown("lightdm.service is inactive".into())
        );
    }

    #[test]
    fn a_unit_without_a_main_process_cannot_be_proven() {
        let mut source = Scripted::live("b".repeat(32).as_str());
        let mut no_pid = observation("b".repeat(32).as_str());
        no_pid.main_pid = 0;
        source.first = Some(no_pid.clone());
        source.second = Some(no_pid);
        assert_eq!(
            evaluate(&source),
            Verdict::Unknown("unit has no main process".into())
        );
    }

    #[test]
    fn a_restart_between_the_samples_is_detected_by_identity_not_time() {
        let mut source = Scripted::live("b".repeat(32).as_str());
        let mut restarted = observation(&"c".repeat(32));
        restarted.main_pid = 4212;
        restarted.exec_start_monotonic_us = 987_654_322;
        source.second = Some(restarted);
        assert_eq!(
            evaluate(&source),
            Verdict::Unknown("invocation changed during the observation".into())
        );
    }

    #[test]
    fn a_receipt_from_an_earlier_invocation_is_refused() {
        let mut source = Scripted::live("b".repeat(32).as_str());
        source.receipt = Some(Ok(
            Receipt::from_json(&receipt_json(&"a".repeat(32))).unwrap()
        ));
        assert_eq!(
            evaluate(&source),
            Verdict::Unknown("receipt does not name the current invocation".into())
        );
    }

    #[test]
    fn a_dead_target_between_the_samples_is_unknown() {
        let mut source = Scripted::live("b".repeat(32).as_str());
        source.alive_limit = 0;
        assert_eq!(
            evaluate(&source),
            Verdict::Unknown("target lifetime unconfirmed".into())
        );
    }

    #[test]
    fn an_unobservable_manager_is_unknown() {
        let mut source = Scripted::live("b".repeat(32).as_str());
        source.first = None;
        assert_eq!(
            evaluate(&source),
            Verdict::Unknown("manager observation unavailable".into())
        );
        let mut source = Scripted::live("b".repeat(32).as_str());
        source.second = None;
        assert_eq!(
            evaluate(&source),
            Verdict::Unknown("second manager observation unavailable".into())
        );
    }

    #[test]
    fn a_receipt_the_reader_cannot_trust_whole_is_unknown() {
        let mut source = Scripted::live("b".repeat(32).as_str());
        source.receipt = Some(Err("receipt: unknown field `extra`".into()));
        assert_eq!(
            evaluate(&source),
            Verdict::Unknown("receipt: unknown field `extra`".into())
        );
    }

    #[test]
    fn receipts_refuse_future_schemas_unknown_fields_and_malformed_identity() {
        let future = receipt_json(&"b".repeat(32)).replace("\"schema\":1", "\"schema\":2");
        assert!(Receipt::from_json(&future).is_err());
        let unknown_field = receipt_json(&"b".repeat(32)).replace(
            "\"producer_version\":\"0\"",
            "\"producer_version\":\"0\",\"extra\":1",
        );
        assert!(Receipt::from_json(&unknown_field).is_err());
        for broken in [
            receipt_json(&"b".repeat(31)),
            receipt_json(&"B".repeat(32)).replace("\"main_pid\":4211", "\"main_pid\":0"),
            receipt_json(&"b".repeat(32)).replace(&"a".repeat(64), &"a".repeat(63)),
            receipt_json(&"b".repeat(32)).replace(
                "\"config_generation\":\"g-7\"",
                "\"config_generation\":\"\"",
            ),
        ] {
            assert!(Receipt::from_json(&broken).is_err(), "accepted: {broken}");
        }
    }

    #[test]
    fn a_receipt_for_another_unit_is_refused() {
        let other = receipt_json(&"b".repeat(32))
            .replace("\"unit\":\"lightdm.service\"", "\"unit\":\"sddm.service\"");
        assert!(Receipt::from_json(&other).is_err());
    }

    #[test]
    fn root_and_unprivileged_sources_with_the_same_facts_agree() {
        // Same facts, two source flavors: the verdict is a pure function of
        // the facts, which is the parity requirement.
        let root = Scripted::live("b".repeat(32).as_str());
        let mut unprivileged = Scripted::live("b".repeat(32).as_str());
        unprivileged.receipt = Some(Ok(root.receipt.clone().unwrap().unwrap()));
        assert_eq!(evaluate(&root), evaluate(&unprivileged));
    }

    #[test]
    fn receipts_round_trip_through_their_canonical_form() {
        let receipt = Receipt::from_json(&receipt_json(&"b".repeat(32))).unwrap();
        let round = Receipt::from_json(&serde_json::to_string(&receipt).unwrap()).unwrap();
        assert_eq!(receipt, round);
    }

    #[test]
    fn verdicts_describe_themselves_for_reports() {
        assert_eq!(
            Verdict::Unknown("no managed-start receipt".into()).to_string(),
            "unknown: no managed-start receipt"
        );
        assert_eq!(Verdict::Absent.to_string(), "absent");
        assert_eq!(
            Verdict::VerifiedOff {
                invocation_id: "b".repeat(32),
                config_generation: "g-7".into()
            }
            .to_string(),
            "verified-off"
        );
    }
}
