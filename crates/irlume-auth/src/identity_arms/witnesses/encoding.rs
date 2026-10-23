// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::WitnessError;
use crate::identity_arms::{
    DarkGrant, DarkVerdict, IdentityThresholds, IrArm, IrArms, IrMatch, LitGrant, LitIrDecision,
    LitVerdict, RgbDecision,
};
use irlume_core::fusion::Fusion;
use irlume_core::{calib::IrCalibration, storage::Enrollment};

#[derive(Default)]
pub(super) struct Writer(Vec<u8>);

impl Writer {
    pub(super) fn byte(&mut self, value: u8) {
        self.0.push(value);
    }
    pub(super) fn boolean(&mut self, value: bool) {
        self.byte(u8::from(value));
    }
    pub(super) fn float(&mut self, value: f32) {
        self.0.extend_from_slice(&value.to_bits().to_le_bytes());
    }
    pub(super) fn count(&mut self, value: usize) -> Result<(), WitnessError> {
        self.0.extend_from_slice(
            &u64::try_from(value)
                .map_err(|_| WitnessError::SizeOverflow)?
                .to_le_bytes(),
        );
        Ok(())
    }
    pub(super) fn text(&mut self, value: &str) -> Result<(), WitnessError> {
        self.count(value.len())?;
        self.0.extend_from_slice(value.as_bytes());
        Ok(())
    }
    pub(super) fn finish(self) -> Vec<u8> {
        self.0
    }
}

fn vector(out: &mut Writer, values: &[f32]) -> Result<(), WitnessError> {
    out.count(values.len())?;
    for value in values {
        out.float(*value);
    }
    Ok(())
}

fn optional_text(out: &mut Writer, value: Option<&str>) -> Result<(), WitnessError> {
    out.boolean(value.is_some());
    if let Some(value) = value {
        out.text(value)?;
    }
    Ok(())
}

fn calibration(out: &mut Writer, value: Option<&IrCalibration>) -> Result<(), WitnessError> {
    out.boolean(value.is_some());
    if let Some(IrCalibration {
        m,
        n_rows,
        lambda,
        fitted_pairs,
    }) = value
    {
        for rows in [m, n_rows] {
            out.count(rows.len())?;
            for row in rows {
                vector(out, row)?;
            }
        }
        out.float(*lambda);
        out.count(*fitted_pairs)?;
    }
    Ok(())
}

// Record the actual synthetic matching inputs, not merely a scenario label.
// In particular, different zero-template refusals must not be interchangeable.
pub(super) fn enrollment(out: &mut Writer, value: &Enrollment) -> Result<(), WitnessError> {
    out.count(value.profiles.len())?;
    for profile in &value.profiles {
        out.text(&profile.name)?;
        out.count(profile.scans.len())?;
        for scan in &profile.scans {
            out.text(&scan.name)?;
            vector(out, &scan.rgb)?;
            out.boolean(scan.ir.is_some());
            if let Some(ir) = &scan.ir {
                vector(out, ir)?;
            }
            optional_text(out, scan.ir_space.as_deref())?;
            optional_text(out, scan.embed_space.as_deref())?;
        }
        calibration(out, profile.ir_calib.as_ref())?;
        out.count(profile.ir_calibs.len())?;
        for (space, value) in &profile.ir_calibs {
            out.text(space)?;
            calibration(out, Some(value))?;
        }
    }
    Ok(())
}

pub(super) fn fusion(out: &mut Writer, value: &Fusion) {
    let Fusion {
        prob,
        p_rgb,
        p_ir,
        grant,
    } = value;
    for value in [prob, p_rgb, p_ir] {
        out.float(*value);
    }
    out.boolean(*grant);
}

pub(super) fn matched(out: &mut Writer, value: &IrMatch) -> Result<(), WitnessError> {
    let IrMatch {
        best,
        best_who,
        n_templates,
        centroid,
    } = value;
    out.float(*best);
    out.text(best_who)?;
    out.count(*n_templates)?;
    out.boolean(centroid.is_some());
    if let Some((score, who)) = centroid {
        out.float(*score);
        out.text(who)?;
    }
    Ok(())
}

pub(super) fn lit(out: &mut Writer, value: &LitVerdict) -> Result<(), WitnessError> {
    match value.grant() {
        None => out.byte(0),
        Some(grant) => {
            let (tag, score, who) = match grant {
                LitGrant::Rgb { score, who } => (1, score, who),
                LitGrant::Fusion { score, who } => (2, score, who),
                LitGrant::Fallback { score, who } => (3, score, who),
                LitGrant::Centroid { score, who } => (4, score, who),
            };
            out.byte(tag);
            out.float(score);
            out.text(who)?;
        }
    }
    let LitVerdict { rgb, ir } = value;
    let RgbDecision {
        score,
        who,
        templates,
        threshold,
        grants,
        deferred,
    } = rgb;
    out.float(*score);
    out.text(who)?;
    out.count(*templates)?;
    out.float(*threshold);
    out.boolean(*grants);
    out.boolean(*deferred);
    out.boolean(ir.is_some());
    if let Some(LitIrDecision {
        matched: ir_match,
        arms,
        fusion_deferred,
    }) = ir
    {
        matched(out, ir_match)?;
        let IrArms {
            fusion: result,
            fallback_threshold,
            centroid_threshold,
            grant,
        } = arms;
        fusion(out, result);
        out.float(*fallback_threshold);
        out.boolean(centroid_threshold.is_some());
        if let Some(threshold) = centroid_threshold {
            out.float(*threshold);
        }
        out.byte(match grant {
            None => 0,
            Some(IrArm::Fusion) => 1,
            Some(IrArm::Fallback) => 2,
            Some(IrArm::Centroid) => 3,
        });
        out.boolean(*fusion_deferred);
    }
    Ok(())
}

pub(super) fn dark(out: &mut Writer, value: &DarkVerdict<'_>) -> Result<(), WitnessError> {
    let DarkVerdict {
        thresholds,
        best,
        centroid,
        grant,
    } = value;
    let IdentityThresholds {
        best: best_threshold,
        centroid: centroid_threshold,
    } = thresholds;
    out.float(*best_threshold);
    out.float(*centroid_threshold);
    out.boolean(*best);
    out.boolean(*centroid);
    match grant {
        None => out.byte(0),
        Some(grant) => {
            let (tag, score, who) = match grant {
                DarkGrant::Best { score, who } => (1, score, who),
                DarkGrant::Centroid { score, who } => (2, score, who),
            };
            out.byte(tag);
            out.float(*score);
            out.text(who)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_uses_fixed_width_lengths_and_float_bits() {
        let mut out = Writer::default();
        out.text("ab").unwrap();
        out.float(-0.0);
        out.boolean(true);
        let mut expected = 2u64.to_le_bytes().to_vec();
        expected.extend_from_slice(b"ab");
        expected.extend_from_slice(&(-0.0f32).to_bits().to_le_bytes());
        expected.push(1);
        assert_eq!(out.finish(), expected);
    }

    #[test]
    fn lit_encoding_observes_unselected_fields_as_well_as_the_grant() {
        let input = super::super::inputs::fusion_winner(0.5, 60.0, 35.0);
        let mut verdict = input.lit();
        let encode = |v: &LitVerdict| {
            let mut out = Writer::default();
            lit(&mut out, v).unwrap();
            out.finish()
        };
        let original = encode(&verdict);
        verdict.rgb.deferred = !verdict.rgb.deferred;
        assert_ne!(encode(&verdict), original);
        verdict.rgb.deferred = !verdict.rgb.deferred;
        verdict.ir.as_mut().unwrap().arms.fallback_threshold += 0.01;
        assert_ne!(encode(&verdict), original);
    }
}
