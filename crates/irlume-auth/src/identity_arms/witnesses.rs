// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

mod cases;
mod encoding;
mod inputs;

use crate::identity_arms::{dark_verdict, IrMatch, LitVerdict};
use encoding::Writer;

pub(super) const MAX_COMPOSED_CASES: usize = 1024;
const FAMILY_COUNTS: [usize; 12] = [24, 48, 18, 24, 9, 360, 11, 12, 5, 4, 4, 8];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Record {
    pub(super) family: u8,
    pub(super) index: usize,
    pub(super) bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WitnessError {
    SizeOverflow,
    BudgetExceeded,
    MissingCoverage,
}

struct Collector {
    records: Vec<Record>,
    budget: usize,
}

impl Collector {
    fn push(&mut self, family: u8, out: Writer) -> Result<(), WitnessError> {
        if self.records.len() >= self.budget {
            return Err(WitnessError::BudgetExceeded);
        }
        let index = match self.records.last() {
            Some(last) if last.family > family => return Err(WitnessError::MissingCoverage),
            Some(last) if last.family == family => last
                .index
                .checked_add(1)
                .ok_or(WitnessError::SizeOverflow)?,
            _ => 0,
        };
        self.records.push(Record {
            family,
            index,
            bytes: out.finish(),
        });
        Ok(())
    }

    fn input(
        &mut self,
        family: u8,
        input: &inputs::Inputs,
        check: impl FnOnce(&LitVerdict, Option<&IrMatch>) -> bool,
    ) -> Result<(), WitnessError> {
        let lit = input.lit();
        let matched = input.ir_present.then(|| input.matched());
        if !check(&lit, matched.as_ref()) {
            return Err(WitnessError::MissingCoverage);
        }
        let mut out = Writer::default();
        out.boolean(input.adapter);
        out.boolean(input.sequential);
        out.boolean(input.ir_present);
        out.float(input.rgb_brightness);
        out.float(input.ir_brightness);
        encoding::enrollment(&mut out, &input.enrollment)?;
        out.count(input.rgb.len())?;
        for value in &input.rgb {
            out.float(*value);
        }
        out.count(input.ir.len())?;
        for value in &input.ir {
            out.float(*value);
        }
        encoding::lit(&mut out, &lit)?;
        out.boolean(matched.is_some());
        if let Some(matched) = matched {
            encoding::matched(&mut out, &matched)?;
            encoding::dark(
                &mut out,
                &dark_verdict(&matched, input.enrollment.profiles.len(), input.adapter),
            )?;
        }
        self.push(family, out)
    }
}

pub(super) fn build() -> Result<Vec<Record>, WitnessError> {
    build_with_budget(MAX_COMPOSED_CASES)
}

fn build_with_budget(budget: usize) -> Result<Vec<Record>, WitnessError> {
    let expected = FAMILY_COUNTS
        .iter()
        .try_fold(0usize, |sum, n| sum.checked_add(*n))
        .ok_or(WitnessError::SizeOverflow)?;
    if budget > MAX_COMPOSED_CASES || expected > budget {
        return Err(WitnessError::BudgetExceeded);
    }
    let mut collector = Collector {
        records: Vec::with_capacity(expected),
        budget,
    };
    cases::boundaries(&mut collector)?;
    cases::dark_grid(&mut collector)?;
    cases::fusion_boundaries(&mut collector)?;
    cases::scenarios(&mut collector)?;
    validate(&collector.records)?;
    Ok(collector.records)
}

fn validate(records: &[Record]) -> Result<(), WitnessError> {
    let mut cursor = 0;
    for (family, count) in FAMILY_COUNTS.iter().enumerate() {
        for index in 0..*count {
            let record = records.get(cursor).ok_or(WitnessError::MissingCoverage)?;
            if usize::from(record.family) != family
                || record.index != index
                || record.bytes.is_empty()
            {
                return Err(WitnessError::MissingCoverage);
            }
            cursor += 1;
        }
    }
    if cursor != records.len() {
        return Err(WitnessError::MissingCoverage);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_records_are_complete_bounded_and_deterministic() {
        let first = build().unwrap();
        let second = build().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 527);
        assert!(first.len() <= MAX_COMPOSED_CASES);
        assert!(first
            .windows(2)
            .all(|w| (w[0].family, w[0].index) < (w[1].family, w[1].index)));
    }

    #[test]
    fn witness_budget_and_missing_cases_refuse_partial_success() {
        assert_eq!(
            build_with_budget(526).unwrap_err(),
            WitnessError::BudgetExceeded
        );
        assert_eq!(
            build_with_budget(MAX_COMPOSED_CASES + 1).unwrap_err(),
            WitnessError::BudgetExceeded
        );
        let mut records = build().unwrap();
        records.remove(0);
        assert_eq!(validate(&records), Err(WitnessError::MissingCoverage));
    }

    #[test]
    fn every_witness_append_rechecks_its_limit() {
        let mut out = Collector {
            records: Vec::new(),
            budget: 1,
        };
        let bytes = || {
            let mut w = Writer::default();
            w.byte(1);
            w
        };
        out.push(0, bytes()).unwrap();
        assert_eq!(out.push(0, bytes()), Err(WitnessError::BudgetExceeded));
        assert_eq!(out.records.len(), 1);
    }

    #[test]
    fn unavailable_shapes_cannot_substitute_for_each_other() {
        let mut out = Collector {
            records: Vec::new(),
            budget: 3,
        };
        for kind in [
            inputs::Unavailable::NoTemplate,
            inputs::Unavailable::WrongWidth,
            inputs::Unavailable::ForeignTag,
        ] {
            out.input(11, &inputs::unavailable(kind), |_, _| true)
                .unwrap();
        }
        assert_ne!(out.records[0].bytes, out.records[1].bytes);
        assert_ne!(out.records[0].bytes, out.records[2].bytes);
        assert_ne!(out.records[1].bytes, out.records[2].bytes);
    }
}
