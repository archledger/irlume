// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Retained-call scheduling and acceptance; supplied proofs are not OS attestation.

#![cfg(test)]

use super::gpu_reliability_counter_tests::{CallCounter, CounterError, Counts};
use crate::npu::Infer;

pub(super) struct Reference {
    pub(super) input: Vec<f32>,
    pub(super) bits: Vec<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    BeforeEvents,
    AfterRuntime,
    AfterSystem,
}

impl Phase {
    fn index(self) -> usize {
        match self {
            Self::BeforeEvents => 0,
            Self::AfterRuntime => 1,
            Self::AfterSystem => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Boundary {
    Setup,
    BeforeRuntime,
    AfterRuntime,
    BeforeSystem,
    AfterSystem,
    Final,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    Boundary(Boundary),
    Infer { phase: Phase, input: usize },
    RuntimeWait,
    RuntimeProof,
    SystemWait,
    Complete,
    Stopped,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ProtocolError {
    InvalidReference,
    Sequence,
    Boundary,
    Inference(CounterError),
}

#[derive(Debug)]
pub(super) struct Report {
    pub(super) phases: [Counts; 3],
    pub(super) per_input: [[u64; 4]; 3],
    pub(super) proven_event_calls: [u64; 2],
    complete: bool,
}

impl Report {
    pub(super) fn total(&self) -> Counts {
        // Only Protocol constructs this report: disjoint quotas bound every sum
        // to 1000, including a failing attempt (never retried or replaced).
        Counts {
            gpu_wrapper_attempted: self.phases.iter().map(|c| c.gpu_wrapper_attempted).sum(),
            gpu_wrapper_returned_ok: self.phases.iter().map(|c| c.gpu_wrapper_returned_ok).sum(),
            gpu_fully_bit_checked_ok: self.phases.iter().map(|c| c.gpu_fully_bit_checked_ok).sum(),
        }
    }

    /// Process teardown is external evidence: an in-process report cannot prove
    /// its own later exit. This is protocol acceptance, never GPU certification.
    pub(super) fn accepted(&self, normal_teardown: bool) -> bool {
        self.complete
            && normal_teardown
            && self.proven_event_calls == [300, 300]
            && self.per_input == [[100; 4], [75; 4], [75; 4]]
            && self
                .phases
                .iter()
                .zip([400, 300, 300])
                .all(|(counts, quota)| {
                    counts.gpu_wrapper_attempted == quota
                        && counts.gpu_wrapper_returned_ok == quota
                        && counts.gpu_fully_bit_checked_ok == quota
                })
    }
}

/// Borrows one existing request and four immutable baselines for the whole run.
/// Setup/warm-up calls happen before this borrow and never enter these counters.
/// Proof booleans must come from the clock/runtime validators; OS provenance and
/// actual boundary canaries/inventory belong to the controller, not this helper.
pub(super) struct Protocol<'a> {
    model: &'a mut dyn Infer,
    references: &'a [Reference; 4],
    dimension: usize,
    counters: [CallCounter; 3],
    per_input: [[u64; 4]; 3],
    runtime_proven: bool,
    system_proven: bool,
    step: Step,
}

impl<'a> Protocol<'a> {
    /// # Errors
    /// Refuses empty/nonfinite inputs, inconsistent input dimensions or invalid
    /// reference dimensions/bits before making any model call.
    pub(super) fn new(
        model: &'a mut dyn Infer,
        references: &'a [Reference; 4],
        dimension: usize,
    ) -> Result<Self, ProtocolError> {
        if dimension == 0
            || references.iter().any(|reference| {
                reference.input.is_empty()
                    || reference.input.len() != references[0].input.len()
                    || !reference.input.iter().all(|v| v.is_finite())
                    || reference.bits.len() != dimension
                    || !reference
                        .bits
                        .iter()
                        .all(|&v| f32::from_bits(v).is_finite())
            })
        {
            return Err(ProtocolError::InvalidReference);
        }
        Ok(Self {
            model,
            references,
            dimension,
            counters: std::array::from_fn(|_| CallCounter::default()),
            per_input: [[0; 4]; 3],
            runtime_proven: false,
            system_proven: false,
            step: Step::Boundary(Boundary::Setup),
        })
    }

    pub(super) fn next(&self) -> Step {
        self.step
    }

    fn require(&mut self, expected: Step) -> Result<(), ProtocolError> {
        if self.step != expected {
            self.step = Step::Stopped;
            return Err(ProtocolError::Sequence);
        }
        Ok(())
    }

    /// # Errors
    /// Refuses an out-of-order boundary or a missing/failed CPU or inventory check.
    /// Every refusal latches the entire campaign, even after 1000 good calls.
    pub(super) fn boundary(
        &mut self,
        boundary: Boundary,
        cpu_ok: bool,
        inventory_ok: bool,
    ) -> Result<(), ProtocolError> {
        self.require(Step::Boundary(boundary))?;
        self.step = Step::Stopped;
        if !cpu_ok || !inventory_ok {
            return Err(ProtocolError::Boundary);
        }
        self.step = match boundary {
            Boundary::Setup => Step::Infer {
                phase: Phase::BeforeEvents,
                input: 0,
            },
            Boundary::BeforeRuntime => Step::RuntimeWait,
            Boundary::AfterRuntime => Step::Infer {
                phase: Phase::AfterRuntime,
                input: 0,
            },
            Boundary::BeforeSystem => Step::SystemWait,
            Boundary::AfterSystem => Step::Infer {
                phase: Phase::AfterSystem,
                input: 0,
            },
            Boundary::Final => Step::Complete,
        };
        Ok(())
    }

    /// # Errors
    /// Refuses unless the runtime wait follows the pre-event block/boundary.
    /// A timeout may continue operational calls but cannot manufacture proof.
    pub(super) fn runtime_wait_finished(&mut self) -> Result<(), ProtocolError> {
        self.require(Step::RuntimeWait)?;
        self.step = Step::Infer {
            phase: Phase::AfterRuntime,
            input: 0,
        };
        Ok(())
    }

    /// # Errors
    /// Refuses unless the FIRST four post-wait calls have been counted/checked.
    /// The supplied witness must bracket those calls and exclude system sleep.
    pub(super) fn runtime_proof(&mut self, proven: bool) -> Result<(), ProtocolError> {
        self.require(Step::RuntimeProof)?;
        self.runtime_proven = proven;
        self.step = Step::Boundary(Boundary::AfterRuntime);
        Ok(())
    }

    /// # Errors
    /// Refuses outside the system wait, which occurs after exactly 700 calls.
    /// An unproven event allows operational counts only, never accepted coverage.
    pub(super) fn system_proof(&mut self, proven: bool) -> Result<(), ProtocolError> {
        self.require(Step::SystemWait)?;
        self.system_proven = proven;
        self.step = Step::Boundary(Boundary::AfterSystem);
        Ok(())
    }

    /// # Errors
    /// Refuses outside a scheduled call or on any wrapper/output failure. No
    /// extra warm-up, retry, reference replacement or alternate model is exposed.
    pub(super) fn infer(&mut self) -> Result<(), ProtocolError> {
        let Step::Infer { phase, input } = self.step else {
            self.step = Step::Stopped;
            return Err(ProtocolError::Sequence);
        };
        self.step = Step::Stopped;
        let reference = &self.references[input];
        let counter = &mut self.counters[phase.index()];
        counter
            .counted_infer(
                self.model,
                &reference.input,
                self.dimension,
                &reference.bits,
            )
            .map_err(ProtocolError::Inference)?;
        self.per_input[phase.index()][input] += 1;
        self.step = match (phase, counter.counts().gpu_fully_bit_checked_ok) {
            (Phase::BeforeEvents, 400) => Step::Boundary(Boundary::BeforeRuntime),
            (Phase::AfterRuntime, 4) => Step::RuntimeProof,
            (Phase::AfterRuntime, 300) => Step::Boundary(Boundary::BeforeSystem),
            (Phase::AfterSystem, 300) => Step::Boundary(Boundary::Final),
            _ => Step::Infer {
                phase,
                input: (input + 1) % 4,
            },
        };
        Ok(())
    }

    pub(super) fn report(&self) -> Report {
        let phases = self.counters.each_ref().map(CallCounter::counts);
        Report {
            proven_event_calls: [
                if self.runtime_proven {
                    phases[1].gpu_fully_bit_checked_ok
                } else {
                    0
                },
                if self.system_proven {
                    phases[2].gpu_fully_bit_checked_ok
                } else {
                    0
                },
            ],
            phases,
            per_input: self.per_input,
            complete: self.step == Step::Complete,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npu::Infer;

    #[derive(Default)]
    struct Echo {
        inputs: Vec<Vec<f32>>,
        fault: Option<(usize, Fault)>,
    }

    #[derive(Clone, Copy)]
    enum Fault {
        Wrapper,
        Bits,
    }

    impl Infer for Echo {
        fn infer(&mut self, input: &[f32]) -> Result<Vec<f32>, String> {
            self.inputs.push(input.to_vec());
            if let Some((call, fault)) = self.fault {
                if call == self.inputs.len() {
                    return match fault {
                        Fault::Wrapper => Err("opaque native completion".into()),
                        Fault::Bits => Ok(vec![f32::from_bits(input[0].to_bits() + 1)]),
                    };
                }
            }
            Ok(input.to_vec())
        }
    }

    fn references() -> [Reference; 4] {
        [1.0_f32, 2.0, 3.0, 4.0].map(|value| Reference {
            input: vec![value],
            bits: vec![value.to_bits()],
        })
    }

    #[test]
    fn exact_disjoint_schedule_checks_all_inputs_and_requires_teardown() {
        let mut model = Echo::default();
        let references = references();
        let mut protocol = Protocol::new(&mut model, &references, 1).unwrap();
        let mut phases = [Vec::new(), Vec::new(), Vec::new()];
        let mut boundaries = Vec::new();
        loop {
            match protocol.next() {
                Step::Boundary(boundary) => {
                    boundaries.push(boundary);
                    protocol.boundary(boundary, true, true).unwrap();
                }
                Step::Infer { phase, input } => {
                    phases[phase.index()].push(input);
                    protocol.infer().unwrap();
                }
                Step::RuntimeWait => protocol.runtime_wait_finished().unwrap(),
                Step::RuntimeProof => protocol.runtime_proof(true).unwrap(),
                Step::SystemWait => protocol.system_proof(true).unwrap(),
                Step::Complete => break,
                Step::Stopped => panic!("unexpected refusal"),
            }
        }
        assert_eq!(phases.map(|calls| calls.len()), [400, 300, 300]);
        assert_eq!(
            boundaries,
            [
                Boundary::Setup,
                Boundary::BeforeRuntime,
                Boundary::AfterRuntime,
                Boundary::BeforeSystem,
                Boundary::AfterSystem,
                Boundary::Final
            ]
        );
        let report = protocol.report();
        assert_eq!(report.total(), counts(1000, 1000, 1000));
        assert_eq!(report.per_input, [[100; 4], [75; 4], [75; 4]]);
        assert_eq!(report.proven_event_calls, [300, 300]);
        assert!(!report.accepted(false));
        assert!(report.accepted(true));
        assert_eq!(model.inputs.len(), 1000);
        for (index, input) in model.inputs.iter().enumerate() {
            assert_eq!(input, &references[index % 4].input);
        }
    }

    fn counts(attempted: u64, returned: u64, checked: u64) -> Counts {
        Counts {
            gpu_wrapper_attempted: attempted,
            gpu_wrapper_returned_ok: returned,
            gpu_fully_bit_checked_ok: checked,
        }
    }

    fn step(protocol: &mut Protocol<'_>, runtime: bool, system: bool) {
        match protocol.next() {
            Step::Boundary(boundary) => protocol.boundary(boundary, true, true).unwrap(),
            Step::Infer { .. } => protocol.infer().unwrap(),
            Step::RuntimeWait => protocol.runtime_wait_finished().unwrap(),
            Step::RuntimeProof => protocol.runtime_proof(runtime).unwrap(),
            Step::SystemWait => protocol.system_proof(system).unwrap(),
            Step::Complete | Step::Stopped => panic!("cannot drive a terminal protocol"),
        }
    }

    fn drive_until(protocol: &mut Protocol<'_>, end: Step) {
        for _ in 0..1020 {
            if protocol.next() == end {
                return;
            }
            step(protocol, true, true);
        }
        panic!("protocol did not reach {end:?}");
    }

    #[test]
    fn operational_thousand_without_either_event_is_not_accepted() {
        for (runtime, system, proven) in [
            (false, false, [0, 0]),
            (true, false, [300, 0]),
            (false, true, [0, 300]),
        ] {
            let mut model = Echo::default();
            let references = references();
            let mut protocol = Protocol::new(&mut model, &references, 1).unwrap();
            while protocol.next() != Step::Complete {
                step(&mut protocol, runtime, system);
            }
            let report = protocol.report();
            assert_eq!(report.total(), counts(1000, 1000, 1000));
            assert_eq!(report.proven_event_calls, proven);
            assert!(!report.accepted(true));
        }
    }

    #[test]
    fn first_post_event_cycle_is_counted_before_any_extra_gpu_call() {
        let mut model = Echo::default();
        let references = references();
        let mut protocol = Protocol::new(&mut model, &references, 1).unwrap();
        drive_until(&mut protocol, Step::RuntimeWait);
        assert_eq!(protocol.report().total(), counts(400, 400, 400));
        protocol.runtime_wait_finished().unwrap();
        for input in 0..4 {
            assert_eq!(
                protocol.next(),
                Step::Infer {
                    phase: Phase::AfterRuntime,
                    input
                }
            );
            protocol.infer().unwrap();
            assert_eq!(
                protocol.report().phases[1],
                counts(input as u64 + 1, input as u64 + 1, input as u64 + 1)
            );
            assert_eq!(protocol.report().proven_event_calls, [0, 0]);
        }
        assert_eq!(protocol.next(), Step::RuntimeProof);
        protocol.runtime_proof(true).unwrap();
        assert_eq!(protocol.report().proven_event_calls, [4, 0]);
        drive_until(&mut protocol, Step::SystemWait);
        assert_eq!(protocol.report().total(), counts(700, 700, 700));
        protocol.system_proof(true).unwrap();
        protocol
            .boundary(Boundary::AfterSystem, true, true)
            .unwrap();
        for input in 0..4 {
            assert_eq!(
                protocol.next(),
                Step::Infer {
                    phase: Phase::AfterSystem,
                    input
                }
            );
            protocol.infer().unwrap();
        }
        assert_eq!(protocol.report().total(), counts(704, 704, 704));
        assert_eq!(protocol.report().proven_event_calls, [300, 4]);
        assert!(!protocol.report().accepted(true));
    }

    #[test]
    fn failures_at_phase_edges_preserve_actual_counts_and_stop_without_retry() {
        for call in [1, 400, 401, 404, 405, 700, 701, 704, 1000] {
            for fault in [Fault::Wrapper, Fault::Bits] {
                let mut model = Echo {
                    fault: Some((call, fault)),
                    ..Echo::default()
                };
                let references = references();
                let mut protocol = Protocol::new(&mut model, &references, 1).unwrap();
                loop {
                    if matches!(protocol.next(), Step::Infer { .. }) {
                        if let Err(error) = protocol.infer() {
                            assert_eq!(
                                error,
                                ProtocolError::Inference(match fault {
                                    Fault::Wrapper =>
                                        CounterError::Wrapper("opaque native completion".into()),
                                    Fault::Bits => CounterError::InvalidOutput,
                                })
                            );
                            break;
                        }
                    } else {
                        step(&mut protocol, true, true);
                    }
                }
                let report = protocol.report();
                let attempted = call as u64;
                let returned = attempted - u64::from(matches!(fault, Fault::Wrapper));
                assert_eq!(report.total(), counts(attempted, returned, attempted - 1));
                assert_eq!(
                    report.per_input.iter().flatten().sum::<u64>(),
                    attempted - 1
                );
                assert!(!report.accepted(true));
                assert_eq!(protocol.next(), Step::Stopped);
                assert_eq!(protocol.infer(), Err(ProtocolError::Sequence));
                assert_eq!(protocol.runtime_proof(true), Err(ProtocolError::Sequence));
                assert_eq!(protocol.system_proof(true), Err(ProtocolError::Sequence));
                assert_eq!(protocol.report().total(), report.total());
                assert_eq!(model.inputs.len(), call);
            }
        }
    }

    #[test]
    fn each_cpu_or_inventory_boundary_failure_is_terminal() {
        for (boundary, completed) in [
            (Boundary::Setup, 0),
            (Boundary::BeforeRuntime, 400),
            (Boundary::AfterRuntime, 404),
            (Boundary::BeforeSystem, 700),
            (Boundary::AfterSystem, 700),
            (Boundary::Final, 1000),
        ] {
            for (cpu, inventory) in [(false, true), (true, false), (false, false)] {
                let mut model = Echo::default();
                let references = references();
                let mut protocol = Protocol::new(&mut model, &references, 1).unwrap();
                drive_until(&mut protocol, Step::Boundary(boundary));
                assert_eq!(
                    protocol.boundary(boundary, cpu, inventory),
                    Err(ProtocolError::Boundary)
                );
                assert_eq!(
                    protocol.report().total(),
                    counts(completed, completed, completed)
                );
                assert!(!protocol.report().accepted(true));
                assert_eq!(
                    protocol.boundary(boundary, true, true),
                    Err(ProtocolError::Sequence)
                );
                assert_eq!(protocol.infer(), Err(ProtocolError::Sequence));
                assert_eq!(
                    protocol.report().total(),
                    counts(completed, completed, completed)
                );
            }
        }
    }

    #[test]
    fn no_gpu_calls_may_skip_a_boundary_wait_or_proof() {
        for end in [
            Step::Boundary(Boundary::Setup),
            Step::Boundary(Boundary::BeforeRuntime),
            Step::RuntimeWait,
            Step::RuntimeProof,
            Step::Boundary(Boundary::AfterRuntime),
            Step::Boundary(Boundary::BeforeSystem),
            Step::SystemWait,
            Step::Boundary(Boundary::AfterSystem),
            Step::Boundary(Boundary::Final),
            Step::Complete,
        ] {
            let mut model = Echo::default();
            let references = references();
            let mut protocol = Protocol::new(&mut model, &references, 1).unwrap();
            drive_until(&mut protocol, end);
            let before = protocol.report().total();
            assert_eq!(protocol.infer(), Err(ProtocolError::Sequence));
            assert_eq!(protocol.next(), Step::Stopped);
            assert_eq!(protocol.report().total(), before);
            assert!(!protocol.report().accepted(true));
        }
    }

    #[test]
    fn premature_or_replayed_proofs_cannot_qualify_calls() {
        for end in [
            Step::Boundary(Boundary::Setup),
            Step::RuntimeWait,
            Step::Boundary(Boundary::AfterRuntime),
            Step::Boundary(Boundary::AfterSystem),
            Step::Complete,
        ] {
            for operation in 0..3 {
                let mut model = Echo::default();
                let references = references();
                let mut protocol = Protocol::new(&mut model, &references, 1).unwrap();
                drive_until(&mut protocol, end);
                let before = protocol.report().total();
                let result = match operation {
                    0 => protocol.runtime_proof(true),
                    1 => protocol.system_proof(true),
                    2 => protocol.boundary(Boundary::Final, true, true),
                    _ => unreachable!(),
                };
                assert_eq!(result, Err(ProtocolError::Sequence));
                assert_eq!(protocol.report().total(), before);
                assert!(!protocol.report().accepted(true));
            }
        }
    }

    #[test]
    fn setup_baselines_warmup_and_cpu_are_excluded_from_protocol_counts() {
        let mut model = Echo::default();
        let mut cpu = Echo::default();
        let references = references();
        for reference in &references {
            model.infer(&reference.input).unwrap();
            model.infer(&reference.input).unwrap();
            cpu.infer(&reference.input).unwrap();
        }
        let before: Vec<_> = references
            .iter()
            .map(|r| (r.input.clone(), r.bits.clone()))
            .collect();
        let mut protocol = Protocol::new(&mut model, &references, 1).unwrap();
        assert_eq!(protocol.report().total(), Counts::default());
        while protocol.next() != Step::Complete {
            cpu.infer(&references[0].input).unwrap();
            step(&mut protocol, true, true);
        }
        assert_eq!(protocol.report().total(), counts(1000, 1000, 1000));
        assert_eq!(model.inputs.len(), 1008);
        assert!(cpu.inputs.len() > 1000);
        assert_eq!(
            references
                .iter()
                .map(|r| (r.input.clone(), r.bits.clone()))
                .collect::<Vec<_>>(),
            before
        );
    }

    #[test]
    fn invalid_baselines_refuse_before_any_call() {
        for slot in 0..4 {
            for invalid in 0..7 {
                let mut model = Echo::default();
                let mut references = references();
                let mut dimension = 1;
                match invalid {
                    0 => references[slot].input.clear(),
                    1 => references[slot].input.push(1.0),
                    2 => references[slot].input[0] = f32::NAN,
                    3 => references[slot].bits.clear(),
                    4 => references[slot].bits.push(1.0_f32.to_bits()),
                    5 => references[slot].bits[0] = f32::INFINITY.to_bits(),
                    6 => dimension = 0,
                    _ => unreachable!(),
                }
                assert!(matches!(
                    Protocol::new(&mut model, &references, dimension),
                    Err(ProtocolError::InvalidReference)
                ));
                assert!(model.inputs.is_empty());
            }
        }
    }
}
