// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Pure caller-observable counters, not reliability qualification or native-stage counts.
//! The caller keeps baseline/warm-up/CPU calls separate and supplies immutable
//! reference bits. This helper never replaces a call or establishes a baseline.

#![cfg(test)]

use crate::npu::Infer;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Counts {
    pub(super) gpu_wrapper_attempted: u64,
    pub(super) gpu_wrapper_returned_ok: u64,
    pub(super) gpu_fully_bit_checked_ok: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum CounterError {
    Stopped,
    InvalidReference,
    CounterOverflow,
    // Native completion on Err is unknown. Keep the wrapper error opaque.
    Wrapper(String),
    InvalidOutput,
}

#[derive(Default)]
pub(super) struct CallCounter {
    counts: Counts,
    stopped: bool,
}

impl CallCounter {
    pub(super) fn counts(&self) -> Counts {
        self.counts
    }

    /// Count one wrapper call against the caller's unchanged reference.
    ///
    /// # Errors
    ///
    /// Refuses after any failure, on an invalid reference or counter overflow,
    /// on wrapper error, or when output dimensions, finiteness or bits differ.
    pub(super) fn counted_infer(
        &mut self,
        model: &mut dyn Infer,
        input: &[f32],
        expected_len: usize,
        expected_bits: &[u32],
    ) -> Result<(), CounterError> {
        if self.stopped {
            return Err(CounterError::Stopped);
        }
        // Latch before any fallible work; only a fully checked call clears it.
        self.stopped = true;
        if expected_len == 0
            || expected_bits.len() != expected_len
            || !expected_bits.iter().all(|&v| f32::from_bits(v).is_finite())
        {
            return Err(CounterError::InvalidReference);
        }
        // Reserve representability before calling, without recording success.
        let next = |v: u64| v.checked_add(1).ok_or(CounterError::CounterOverflow);
        let attempted = next(self.counts.gpu_wrapper_attempted)?;
        let returned = next(self.counts.gpu_wrapper_returned_ok)?;
        let checked = next(self.counts.gpu_fully_bit_checked_ok)?;
        self.counts.gpu_wrapper_attempted = attempted;
        let output = model.infer(input).map_err(CounterError::Wrapper)?;
        self.counts.gpu_wrapper_returned_ok = returned;
        if output.len() != expected_len
            || !output
                .iter()
                .zip(expected_bits)
                .all(|(value, &bits)| value.is_finite() && value.to_bits() == bits)
        {
            return Err(CounterError::InvalidOutput);
        }
        self.counts.gpu_fully_bit_checked_ok = checked;
        self.stopped = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const INPUT: [f32; 2] = [3.0, -0.0];
    const REFERENCE: [u32; 2] = [0x3f80_0000, 0x4000_0000];

    impl Counts {
        fn new(attempted: u64, returned: u64, checked: u64) -> Self {
            Self {
                gpu_wrapper_attempted: attempted,
                gpu_wrapper_returned_ok: returned,
                gpu_fully_bit_checked_ok: checked,
            }
        }
    }

    enum Reply {
        ErrorBeforeNative,
        ErrorAfterNative,
        Output(Vec<f32>),
    }

    struct Fake {
        replies: VecDeque<Reply>,
        calls: u64,
        native_successes: u64,
        inputs: Vec<Vec<u32>>,
    }

    impl Fake {
        fn new(reply: Reply) -> Self {
            Self {
                replies: [reply, Reply::Output(vec![1.0, 2.0])].into(),
                calls: 0,
                native_successes: 0,
                inputs: Vec::new(),
            }
        }
    }

    impl Infer for Fake {
        fn infer(&mut self, input: &[f32]) -> Result<Vec<f32>, String> {
            self.calls += 1;
            self.inputs
                .push(input.iter().map(|v| v.to_bits()).collect());
            match self.replies.pop_front().expect("unexpected extra call") {
                Reply::ErrorBeforeNative => Err("opaque wrapper error".into()),
                Reply::ErrorAfterNative => {
                    self.native_successes += 1;
                    Err("opaque wrapper error".into())
                }
                Reply::Output(output) => {
                    self.native_successes += 1;
                    Ok(output)
                }
            }
        }
    }

    fn assert_stopped(counter: &mut CallCounter, model: &mut Fake) {
        let counts = counter.counts();
        let calls = model.calls;
        assert!(counter.stopped);
        assert_eq!(
            counter.counted_infer(model, &INPUT, 2, &REFERENCE),
            Err(CounterError::Stopped)
        );
        assert_eq!(counter.counts(), counts);
        assert_eq!(model.calls, calls);
        assert_eq!(model.replies.len(), 1, "no replacement inference");
    }

    #[test]
    fn error_before_native_has_only_one_wrapper_attempt() {
        let mut counter = CallCounter::default();
        let mut model = Fake::new(Reply::ErrorBeforeNative);
        assert_eq!(
            counter.counted_infer(&mut model, &INPUT, 2, &REFERENCE),
            Err(CounterError::Wrapper("opaque wrapper error".into()))
        );
        assert_eq!(counter.counts, Counts::new(1, 0, 0));
        assert_eq!((model.calls, model.native_successes), (1, 0));
        assert_stopped(&mut counter, &mut model);
    }

    #[test]
    fn error_after_fake_native_success_has_identical_caller_counts() {
        let mut counter = CallCounter::default();
        let mut model = Fake::new(Reply::ErrorAfterNative);
        assert_eq!(
            counter.counted_infer(&mut model, &INPUT, 2, &REFERENCE),
            Err(CounterError::Wrapper("opaque wrapper error".into()))
        );
        assert_eq!(counter.counts, Counts::new(1, 0, 0));
        assert_eq!((model.calls, model.native_successes), (1, 1));
        assert_stopped(&mut counter, &mut model);
    }

    #[test]
    fn returned_ok_invalid_outputs_count_wrapper_ok_but_stop() {
        for output in [
            vec![],
            vec![1.0],
            vec![1.0, 2.0, 3.0],
            vec![f32::NAN, 2.0],
            vec![1.0, f32::INFINITY],
            vec![1.0, f32::NEG_INFINITY],
            vec![1.0, f32::from_bits(REFERENCE[1] + 1)],
        ] {
            let mut counter = CallCounter::default();
            let mut model = Fake::new(Reply::Output(output));
            assert_eq!(
                counter.counted_infer(&mut model, &INPUT, 2, &REFERENCE),
                Err(CounterError::InvalidOutput)
            );
            assert_eq!(counter.counts, Counts::new(1, 1, 0));
            assert_eq!(model.calls, 1);
            assert_stopped(&mut counter, &mut model);
        }
    }

    #[test]
    fn signed_zero_difference_is_not_bit_checked_success() {
        let mut counter = CallCounter::default();
        let mut model = Fake::new(Reply::Output(vec![-0.0]));
        assert_eq!(
            counter.counted_infer(&mut model, &INPUT, 1, &[0.0_f32.to_bits()]),
            Err(CounterError::InvalidOutput)
        );
        assert_eq!(counter.counts, Counts::new(1, 1, 0));
        assert_stopped(&mut counter, &mut model);
    }

    #[test]
    fn success_counts_all_three_and_preserves_input_and_reference_bits() {
        let mut counter = CallCounter::default();
        let mut model = Fake::new(Reply::Output(vec![1.0, 2.0]));
        let input = INPUT;
        let reference = REFERENCE;
        let input_before = input.map(f32::to_bits);
        let reference_before = reference;
        assert_eq!(
            counter.counted_infer(&mut model, &input, 2, &reference),
            Ok(())
        );
        assert_eq!(counter.counts, Counts::new(1, 1, 1));
        assert!(!counter.stopped);
        assert_eq!(model.inputs, vec![input_before.to_vec()]);
        model.replies[0] = Reply::ErrorAfterNative;
        assert!(counter
            .counted_infer(&mut model, &input, 2, &reference)
            .is_err());
        assert_eq!(counter.counts, Counts::new(2, 1, 1));
        assert_eq!(input.map(f32::to_bits), input_before);
        assert_eq!(reference, reference_before);
        model.replies.push_back(Reply::Output(vec![1.0, 2.0]));
        assert_stopped(&mut counter, &mut model);
    }

    #[test]
    fn invalid_reference_stops_before_any_attempt() {
        for (dimension, reference) in [
            (0, vec![]),
            (1, vec![]),
            (1, REFERENCE.to_vec()),
            (1, vec![f32::NAN.to_bits()]),
            (1, vec![f32::INFINITY.to_bits()]),
            (1, vec![f32::NEG_INFINITY.to_bits()]),
        ] {
            let mut counter = CallCounter::default();
            let mut model = Fake::new(Reply::Output(vec![1.0, 2.0]));
            assert_eq!(
                counter.counted_infer(&mut model, &INPUT, dimension, &reference),
                Err(CounterError::InvalidReference)
            );
            assert_eq!(counter.counts, Counts::new(0, 0, 0));
            assert_eq!(model.calls, 0);
            // Leave one unused fixture for the same stopped-state assertion.
            model.replies.pop_back();
            assert_stopped(&mut counter, &mut model);
        }
    }

    #[test]
    fn counter_overflow_refuses_before_call_without_fabricated_success() {
        for counts in [
            Counts::new(u64::MAX, 0, 0),
            Counts::new(0, u64::MAX, 0),
            Counts::new(0, 0, u64::MAX),
        ] {
            let mut counter = CallCounter {
                counts,
                stopped: false,
            };
            let mut model = Fake::new(Reply::Output(vec![1.0, 2.0]));
            assert_eq!(
                counter.counted_infer(&mut model, &INPUT, 2, &REFERENCE),
                Err(CounterError::CounterOverflow)
            );
            assert_eq!(counter.counts, counts);
            assert_eq!(model.calls, 0);
            model.replies.pop_back();
            assert_stopped(&mut counter, &mut model);
        }
    }

    #[test]
    fn last_representable_success_then_overflow_preserves_actual_counts() {
        let mut counter = CallCounter {
            counts: Counts::new(u64::MAX - 1, u64::MAX - 1, u64::MAX - 1),
            stopped: false,
        };
        let mut model = Fake::new(Reply::Output(vec![1.0, 2.0]));
        assert_eq!(
            counter.counted_infer(&mut model, &INPUT, 2, &REFERENCE),
            Ok(())
        );
        assert_eq!(
            counter.counted_infer(&mut model, &INPUT, 2, &REFERENCE),
            Err(CounterError::CounterOverflow)
        );
        assert_eq!(counter.counts, Counts::new(u64::MAX, u64::MAX, u64::MAX));
        assert_eq!(model.calls, 1);
        assert_stopped(&mut counter, &mut model);
    }

    #[test]
    fn baseline_warmup_and_cpu_calls_are_caller_separated() {
        let mut counter = CallCounter::default();
        let mut model = Fake::new(Reply::Output(vec![1.0, 2.0]));
        let mut cpu = Fake::new(Reply::Output(vec![1.0, 2.0]));
        assert!(model.infer(&INPUT).is_ok());
        assert!(model.infer(&INPUT).is_ok());
        assert!(cpu.infer(&INPUT).is_ok());
        assert_eq!(counter.counts, Counts::new(0, 0, 0));
        model.replies.push_back(Reply::Output(vec![1.0, 2.0]));
        assert_eq!(
            counter.counted_infer(&mut model, &INPUT, 2, &REFERENCE),
            Ok(())
        );
        assert_eq!(counter.counts, Counts::new(1, 1, 1));
        assert_eq!((model.calls, cpu.calls), (3, 1));
    }
}
