// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Pure recommendations over hypothetical, caller-asserted recognizer facts.
//!
//! This module verifies no loading admission, device identity, certification or
//! measurement. A recommendation is not a capability or actual placement. It
//! neither discovers devices nor reads files or environment variables. Future
//! production integration must establish the facts independently and preserve
//! every runtime check. No production path consumes these recommendations yet.
//!
//! Keys are opaque bytes, not a new certification-key or hash format. Their
//! completeness and authenticity belong to the caller. Relevant keys must be
//! nonempty and match byte-for-byte, without decoding or normalization.
//!
//! [`recommend`] filters these assertions by the separate switches, then follows
//! an explicit preference or an exact workload-bound order. It never supplies a
//! default accelerator order. Switch filtering is not proof that a runtime
//! collector checked its switch before doing work.

/// The maximum number of candidate records inspected for a recommendation.
pub const MAX_CANDIDATES: usize = 2;

/// The maximum length of a CPU/NPU/GPU evidence order.
pub const MAX_ORDER_TARGETS: usize = 3;

/// An accelerator class, not a physical device identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accelerator {
    /// The NPU class.
    Npu,
    /// The GPU class.
    Gpu,
}

/// The caller's preference, before any recommendation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preference {
    /// Apply the supplied workload-bound evidence order.
    Auto,
    /// Recommend CPU without inspecting candidates or evidence.
    Cpu,
    /// Consider only the NPU class, falling back to CPU on refusal.
    Npu,
    /// Consider only the GPU class, falling back to CPU on refusal.
    Gpu,
}

/// Independent switch assertions. An allowing switch grants no permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Switches {
    /// Whether the caller says the NPU switch allows consideration.
    pub npu: bool,
    /// Whether the caller says the GPU switch allows consideration.
    pub gpu: bool,
}

/// Caller-defined exact candidate identity bytes, not a certification key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateKey<'a>(pub &'a [u8]);

/// Caller-defined model/reference/consumer/compile/measurement scope bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkloadKey<'a>(pub &'a [u8]);

/// A refusal asserted by the caller, never independently verified here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// This build does not support the requested accelerator.
    UnsupportedBuild,
    /// Production native loading has not been admitted.
    LoadingNotAdmitted,
    /// The runtime was reported unavailable.
    RuntimeUnavailable,
    /// The caller could not establish a complete identity.
    IdentityUnavailable,
    /// More than one physical device could satisfy the class selection.
    AmbiguousDevice,
    /// No matching certification was reported.
    NotCertified,
}

/// Hypothetical candidate assessment, not proof of production eligibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Assessment {
    /// The caller supplied no assessment.
    Unobserved,
    /// The caller reported a refusal.
    Refused(Refusal),
    /// The caller asserts eligibility; this module verifies none of it.
    ReportedEligible,
}

/// One caller-asserted candidate for a particular workload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate<'a> {
    /// Class of the candidate.
    pub accelerator: Accelerator,
    /// Exact candidate binding supplied by the caller.
    pub key: CandidateKey<'a>,
    /// Workload for which the assessment was supplied.
    pub workload: WorkloadKey<'a>,
    /// The caller's assessment, not an authorization token.
    pub assessment: Assessment,
}

/// One target in a caller-supplied strict preference order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderedTarget<'a> {
    /// The CPU reference bound by the evidence workload.
    Cpu,
    /// An exact candidate within an accelerator class.
    Accelerator {
        /// Candidate class.
        accelerator: Accelerator,
        /// Exact candidate binding, compared byte-for-byte.
        key: CandidateKey<'a>,
    },
}

/// A hypothetical evidence order; provenance is not verified here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceOrder<'a> {
    /// Workload this order describes.
    pub workload: WorkloadKey<'a>,
    /// At most three targets, CPU exactly once and no repeated class.
    pub targets: &'a [OrderedTarget<'a>],
}

/// A recommended target, never actual placement or permission to load it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecommendedTarget<'a> {
    /// Keep the CPU reference.
    Cpu,
    /// The matching caller-asserted candidate, with its borrowed key.
    Accelerator {
        /// Class recommended by the supplied facts and preference.
        accelerator: Accelerator,
        /// Borrowed from the candidate, not from the evidence order.
        key: CandidateKey<'a>,
    },
}

/// Why the hypothetical recommendation was made; no raw input is included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The explicit preference was satisfied.
    ExplicitPreference,
    /// The supplied evidence order selected the target, possibly CPU.
    OrderedEvidence,
    /// The requested accelerator's switch forbids consideration.
    SwitchDisabled,
    /// The requested candidate was not assessed.
    Unobserved,
    /// The requested candidate carried this caller-asserted refusal.
    Refused(Refusal),
    /// No candidate for the explicit accelerator preference was supplied.
    MissingCandidate,
    /// Too many records, or a repeated class whose switch allows it.
    AmbiguousCandidates,
    /// A relevant candidate assessment describes a different workload.
    WorkloadMismatch,
    /// A required candidate or workload key is empty.
    InvalidKey,
    /// Auto has an asserted eligible candidate but no evidence order.
    MissingEvidence,
    /// The evidence order describes a different workload.
    EvidenceMismatch,
    /// The order exceeds its bound, repeats a class, omits a required target,
    /// or names an unknown identity for an asserted eligible class.
    InvalidOrder,
    /// Auto has no asserted eligible candidate after switch filtering.
    NoEligibleAccelerator,
}

/// A pure policy answer. It certifies nothing and grants no runtime access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct Recommendation<'a> {
    /// Hypothetical target, not the device currently running any model.
    pub target: RecommendedTarget<'a>,
    /// Structured explanation of the recommendation.
    pub reason: Reason,
}

/// Recommend a target from hypothetical caller assertions, not verified facts.
///
/// Explicit CPU ignores all other inputs. An explicit accelerator's disabled
/// switch returns CPU before inspecting candidates; otherwise only that class
/// is considered, with no substitution of the other accelerator. Explicit
/// preferences do not consume ranking evidence.
///
/// Auto ignores disabled classes and unobserved/refused assessments. A repeated
/// enabled class, an invalid asserted-eligible key or a workload mismatch
/// returns CPU. Candidate input is bounded by [`MAX_CANDIDATES`]. When no class
/// remains, no evidence is required. Otherwise the evidence workload must match
/// and its order must contain CPU exactly once and every asserted-eligible
/// candidate exactly once, with no repeated class and at most
/// [`MAX_ORDER_TARGETS`] entries. Nonempty keys for ineligible order entries
/// may be skipped; an unknown key for an eligible class refuses the whole order.
/// All order entries are checked even when CPU is first.
///
/// The returned key borrows the candidate's bytes, never the evidence's bytes.
/// The result is not admission, certification, permission or actual placement.
pub fn recommend<'a>(
    preference: Preference,
    switches: Switches,
    workload: WorkloadKey<'_>,
    candidates: &[Candidate<'a>],
    evidence: Option<&EvidenceOrder<'_>>,
) -> Recommendation<'a> {
    let cpu = |reason| Recommendation {
        target: RecommendedTarget::Cpu,
        reason,
    };
    let requested = match preference {
        Preference::Cpu => return cpu(Reason::ExplicitPreference),
        Preference::Npu => Some(Accelerator::Npu),
        Preference::Gpu => Some(Accelerator::Gpu),
        Preference::Auto => None,
    };
    if let Some(accelerator) = requested {
        if !switches.allows(accelerator) {
            return cpu(Reason::SwitchDisabled);
        }
    } else if !switches.npu && !switches.gpu {
        return cpu(Reason::NoEligibleAccelerator);
    }
    if candidates.len() > MAX_CANDIDATES {
        return cpu(Reason::AmbiguousCandidates);
    }
    if workload.0.is_empty() {
        return cpu(Reason::InvalidKey);
    }
    if let Some(accelerator) = requested {
        let candidate = match unique_candidate(accelerator, candidates) {
            Ok(Some(candidate)) => candidate,
            Ok(None) => return cpu(Reason::MissingCandidate),
            Err(reason) => return cpu(reason),
        };
        return match assessed_candidate(candidate, workload) {
            Ok(candidate) => Recommendation {
                target: RecommendedTarget::Accelerator {
                    accelerator,
                    key: candidate.key,
                },
                reason: Reason::ExplicitPreference,
            },
            Err(reason) => cpu(reason),
        };
    }

    let mut eligible = [None, None];
    // Class order only makes refusal precedence deterministic; it never ranks
    // candidates. The evidence order below alone chooses among them.
    for accelerator in [Accelerator::Npu, Accelerator::Gpu] {
        if !switches.allows(accelerator) {
            continue;
        }
        let candidate = match unique_candidate(accelerator, candidates) {
            Ok(Some(candidate)) => candidate,
            Ok(None) => continue,
            Err(reason) => return cpu(reason),
        };
        match assessed_candidate(candidate, workload) {
            Ok(candidate) => eligible[accelerator.index()] = Some(candidate),
            Err(Reason::Unobserved | Reason::Refused(_)) => {}
            Err(reason) => return cpu(reason),
        }
    }
    if eligible.iter().all(Option::is_none) {
        return cpu(Reason::NoEligibleAccelerator);
    }
    let Some(evidence) = evidence else {
        return cpu(Reason::MissingEvidence);
    };
    if evidence.workload.0.is_empty() {
        return cpu(Reason::InvalidKey);
    }
    if evidence.workload != workload {
        return cpu(Reason::EvidenceMismatch);
    }
    if evidence.targets.len() > MAX_ORDER_TARGETS {
        return cpu(Reason::InvalidOrder);
    }

    let mut cpu_seen = false;
    let mut seen = [false, false];
    let mut first = None;
    for target in evidence.targets {
        match *target {
            OrderedTarget::Cpu => {
                if cpu_seen {
                    return cpu(Reason::InvalidOrder);
                }
                cpu_seen = true;
                first.get_or_insert(RecommendedTarget::Cpu);
            }
            OrderedTarget::Accelerator { accelerator, key } => {
                let index = accelerator.index();
                if seen[index] {
                    return cpu(Reason::InvalidOrder);
                }
                seen[index] = true;
                if key.0.is_empty() {
                    return cpu(Reason::InvalidKey);
                }
                if let Some(candidate) = eligible[index] {
                    if candidate.key != key {
                        return cpu(Reason::InvalidOrder);
                    }
                    first.get_or_insert(RecommendedTarget::Accelerator {
                        accelerator,
                        key: candidate.key,
                    });
                }
            }
        }
    }
    if !cpu_seen
        || eligible
            .iter()
            .zip(seen)
            .any(|(candidate, seen)| candidate.is_some() && !seen)
    {
        return cpu(Reason::InvalidOrder);
    }
    Recommendation {
        // A valid order contains CPU, so this fallback is defensive only.
        target: first.unwrap_or(RecommendedTarget::Cpu),
        reason: Reason::OrderedEvidence,
    }
}

impl Accelerator {
    fn index(self) -> usize {
        match self {
            Self::Npu => 0,
            Self::Gpu => 1,
        }
    }
}

impl Switches {
    fn allows(self, accelerator: Accelerator) -> bool {
        match accelerator {
            Accelerator::Npu => self.npu,
            Accelerator::Gpu => self.gpu,
        }
    }
}

fn unique_candidate<'a>(
    accelerator: Accelerator,
    candidates: &[Candidate<'a>],
) -> Result<Option<Candidate<'a>>, Reason> {
    let mut matching = candidates
        .iter()
        .filter(|candidate| candidate.accelerator == accelerator);
    let candidate = matching.next().copied();
    if matching.next().is_some() {
        return Err(Reason::AmbiguousCandidates);
    }
    Ok(candidate)
}

fn assessed_candidate<'a>(
    candidate: Candidate<'a>,
    workload: WorkloadKey<'_>,
) -> Result<Candidate<'a>, Reason> {
    match candidate.assessment {
        Assessment::Unobserved => return Err(Reason::Unobserved),
        Assessment::Refused(refusal) => return Err(Reason::Refused(refusal)),
        Assessment::ReportedEligible => {}
    }
    if candidate.key.0.is_empty() || candidate.workload.0.is_empty() {
        return Err(Reason::InvalidKey);
    }
    if candidate.workload != workload {
        return Err(Reason::WorkloadMismatch);
    }
    Ok(candidate)
}

#[cfg(test)]
mod tests;
