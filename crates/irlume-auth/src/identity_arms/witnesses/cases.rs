// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::{encoding, inputs, Collector, WitnessError};
use crate::identity_arms::{
    arm_threshold, dark_verdict, DarkGrant, IrMatch, LitGrant, LitVerdict, ThresholdArm,
};
use irlume_core::fusion;

fn neighbors(value: f32) -> [f32; 3] {
    [value.next_down(), value, value.next_up()]
}

fn arm(value: &LitVerdict) -> u8 {
    match value.grant() {
        None => 0,
        Some(LitGrant::Rgb { .. }) => 1,
        Some(LitGrant::Fusion { .. }) => 2,
        Some(LitGrant::Fallback { .. }) => 3,
        Some(LitGrant::Centroid { .. }) => 4,
    }
}

pub(super) fn boundaries(out: &mut Collector) -> Result<(), WitnessError> {
    for count in [1, 17, 90, 102] {
        let threshold = arm_threshold(
            ThresholdArm::Rgb {
                base: irlume_core::RGB_MATCH_THRESHOLD,
            },
            count,
        );
        for score in neighbors(threshold) {
            for sequential in [false, true] {
                let mut input = inputs::rgb_boundary(count, score);
                input.sequential = sequential;
                out.input(0, &input, |lit, _| {
                    lit.rgb.score.to_bits() == score.to_bits()
                        && lit.rgb.templates == count
                        && arm(lit) == u8::from(!sequential && score >= threshold)
                        && lit.rgb.deferred == (sequential && score >= threshold)
                })?;
            }
        }
    }
    for count in [1, 17, 90, 102] {
        for adapter in [false, true] {
            let threshold = arm_threshold(ThresholdArm::LitFallback { adapter }, count);
            for score in neighbors(threshold) {
                for sequential in [false, true] {
                    let mut input = inputs::fallback_boundary(count, score);
                    input.adapter = adapter;
                    input.sequential = sequential;
                    out.input(1, &input, |lit, matched| {
                        matched.is_some_and(|m| {
                            m.n_templates == count && m.best.to_bits() == score.to_bits()
                        }) && arm(lit) == if score >= threshold { 3 } else { 0 }
                    })?;
                }
            }
        }
    }
    for profiles in [1, 2, 3] {
        let threshold = arm_threshold(ThresholdArm::LitCentroid { adapter: false }, profiles);
        for score in neighbors(threshold) {
            for sequential in [false, true] {
                let mut input = inputs::centroid_boundary(profiles, score);
                input.sequential = sequential;
                out.input(2, &input, |lit, matched| {
                    matched.is_some_and(|m| {
                        m.best < 0.3
                            && m.centroid.as_ref().is_some_and(|(s, who)| {
                                s.to_bits() == score.to_bits() && who == "ir-centroid"
                            })
                    }) && arm(lit) == if score >= threshold { 4 } else { 0 }
                })?;
            }
        }
    }
    for count in [1, 17, 90, 102] {
        for adapter in [false, true] {
            let threshold = arm_threshold(ThresholdArm::DarkBest { adapter }, count);
            for score in neighbors(threshold) {
                let mut input = inputs::fallback_boundary(count, score);
                input.adapter = adapter;
                out.input(3, &input, |_, matched| {
                    matched.is_some_and(|m| {
                        m.best.to_bits() == score.to_bits()
                            && dark_verdict(m, 1, adapter).best == (score >= threshold)
                    })
                })?;
            }
        }
    }
    for profiles in [1, 2, 3] {
        let threshold = arm_threshold(ThresholdArm::DarkCentroid { adapter: false }, profiles);
        for score in neighbors(threshold) {
            let input = inputs::centroid_boundary(profiles, score);
            out.input(4, &input, |_, matched| {
                matched.is_some_and(|m| {
                    m.best < 0.3
                        && m.centroid.as_ref().is_some_and(|(s, who)| {
                            s.to_bits() == score.to_bits() && who == "ir-centroid"
                        })
                        && dark_verdict(m, profiles, false).centroid == (score >= threshold)
                })
            })?;
        }
    }
    Ok(())
}

pub(super) fn dark_grid(out: &mut Collector) -> Result<(), WitnessError> {
    for count in [0, 1, 3, 90, 102] {
        for profiles in [1, 2, 3] {
            for adapter in [false, true] {
                let best_threshold = arm_threshold(ThresholdArm::DarkBest { adapter }, count);
                let centroid_threshold =
                    arm_threshold(ThresholdArm::DarkCentroid { adapter }, profiles);
                for score in neighbors(best_threshold) {
                    for centroid in [
                        None,
                        Some(centroid_threshold.next_down()),
                        Some(centroid_threshold),
                        Some(centroid_threshold.next_up()),
                    ] {
                        let matched = IrMatch {
                            best: score,
                            best_who: "ir-best".into(),
                            n_templates: count,
                            centroid: centroid.map(|s| (s, "ir-centroid".into())),
                        };
                        let verdict = dark_verdict(&matched, profiles, adapter);
                        let best = count > 0 && score >= best_threshold;
                        let center = count > 0 && centroid.is_some_and(|s| s >= centroid_threshold);
                        let selected = match verdict.grant {
                            Some(DarkGrant::Best { score: got, who }) => {
                                best && got.to_bits() == score.to_bits() && who == "ir-best"
                            }
                            Some(DarkGrant::Centroid { score: got, who }) => {
                                !best
                                    && center
                                    && centroid.is_some_and(|s| s.to_bits() == got.to_bits())
                                    && who == "ir-centroid"
                            }
                            None => !best && !center,
                        };
                        if verdict.best != best || verdict.centroid != center || !selected {
                            return Err(WitnessError::MissingCoverage);
                        }
                        let mut bytes = encoding::Writer::default();
                        bytes.count(profiles)?;
                        bytes.boolean(adapter);
                        encoding::matched(&mut bytes, &matched)?;
                        encoding::dark(&mut bytes, &verdict)?;
                        out.push(5, bytes)?;
                    }
                }
            }
        }
    }
    Ok(())
}

pub(super) fn fusion_boundaries(out: &mut Collector) -> Result<(), WitnessError> {
    let floor = fusion::FUSION_MIN_PER_MODALITY_PROB;
    let threshold = fusion::FUSION_PROB_THRESHOLD;
    let mut samples = Vec::with_capacity(11);
    for p in neighbors(floor) {
        samples.push((p, 0.0, 0.9, 1.0, p >= floor, None));
    }
    for p in neighbors(floor) {
        samples.push((0.9, 1.0, p, 0.25, p >= floor, None));
    }
    for p in neighbors(threshold) {
        samples.push((p, 1.0, p, 1.0, p >= threshold, Some(p)));
    }
    for w in [0.0, f32::MIN_POSITIVE] {
        samples.push((1.0, 1.0, 1.0, w, w > 0.0, None));
    }
    for (rgb, wrgb, ir, wir, grants, exact) in samples {
        let result = fusion::fuse(rgb, wrgb, ir, wir);
        if result.grant != grants
            || exact.is_some_and(|p| result.prob.to_bits() != p.to_bits())
            || result.p_rgb.to_bits() != rgb.to_bits()
            || result.p_ir.to_bits() != ir.to_bits()
        {
            return Err(WitnessError::MissingCoverage);
        }
        let mut bytes = encoding::Writer::default();
        for v in [rgb, wrgb, ir, wir] {
            bytes.float(v);
        }
        encoding::fusion(&mut bytes, &result);
        out.push(6, bytes)?;
    }
    Ok(())
}

pub(super) fn scenarios(out: &mut Collector) -> Result<(), WitnessError> {
    for ir in [0.4, 0.5, 0.6] {
        for rgb_brightness in [60.0, 130.0] {
            for ir_brightness in [35.0, 110.0] {
                let input = inputs::fusion_winner(ir, rgb_brightness, ir_brightness);
                out.input(7, &input, |lit, _| {
                    let who = if ir < 0.5 { "rgb-winner" } else { "ir-winner" };
                    lit.rgb.score.to_bits() == 0.5f32.to_bits() && lit.ir.as_ref().is_some_and(|r| r.matched.best.to_bits() == ir.to_bits())
                        && matches!(lit.grant(), Some(LitGrant::Fusion { who: got, .. }) if got == who)
                })?;
            }
        }
    }
    for kind in 0..5 {
        let mut input = if kind == 0 {
            inputs::rgb_priority()
        } else if kind == 4 {
            inputs::centroid_boundary(1, 1.0)
        } else {
            inputs::competing()
        };
        if kind == 2 {
            input.sequential = true;
        }
        if kind == 3 {
            input.set_rgb_scores(0.1);
        }
        out.input(8, &input, |lit, matched| {
            let Some(m) = matched else { return false };
            let alternative = crate::identity_arms::lit_ir_arms(
                lit.rgb.score,
                input.rgb_brightness,
                m,
                input.ir_brightness,
                input.sequential,
                input.adapter,
                input.enrollment.profiles.len(),
            );
            let center = m
                .centroid
                .as_ref()
                .zip(alternative.centroid_threshold)
                .is_some_and(|((s, _), t)| *s >= t);
            if !center {
                return false;
            }
            if kind == 4 {
                return m.best < alternative.fallback_threshold && arm(lit) == 4;
            }
            let competing = m.best >= alternative.fallback_threshold
                && m.centroid
                    .as_ref()
                    .is_some_and(|(_, who)| who != &m.best_who);
            let expected = [1, 2, 3, 3][kind];
            competing
                && arm(lit) == expected
                && match kind {
                    0 => lit.ir.is_none() && alternative.fusion.grant && lit.rgb.who != m.best_who,
                    1 => alternative.fusion.grant,
                    2 => lit.ir.as_ref().is_some_and(|ir| ir.fusion_deferred),
                    3 => !alternative.fusion.grant,
                    _ => false,
                }
        })?;
    }
    for adapter in [false, true] {
        for sequential in [false, true] {
            let mut input = inputs::accumulation();
            input.adapter = adapter;
            input.sequential = sequential;
            out.input(9, &input, |lit, matched| {
                lit.rgb.score.to_bits() == 1.0f32.to_bits()
                    && matched
                        .is_some_and(|m| m.n_templates == 1 && m.best.to_bits() == 1.0f32.to_bits())
                    && arm(lit) == if sequential { 3 } else { 1 }
            })?;
        }
    }
    for mixed in [false, true] {
        for adapter in [false, true] {
            let mut input = inputs::provenance(mixed);
            input.adapter = adapter;
            out.input(10, &input, |_, matched| {
                matched.is_some_and(|m| {
                    m.n_templates == 1
                        && if mixed || adapter {
                            m.best.to_bits() == 0.4f32.to_bits() && m.centroid.is_none()
                        } else {
                            m.best.to_bits() != 0.4f32.to_bits() && m.centroid.is_some()
                        }
                })
            })?;
        }
    }
    use inputs::Unavailable;
    for kind in [
        Unavailable::NoProbe,
        Unavailable::NoTemplate,
        Unavailable::ForeignTag,
        Unavailable::ForeignRecognizer,
        Unavailable::WrongWidth,
        Unavailable::ZeroAdaptedProbe,
        Unavailable::Empty,
        Unavailable::MalformedCalibration,
    ] {
        let input = inputs::unavailable(kind);
        out.input(11, &input, |lit, matched| {
            arm(lit) == 0
                && match kind {
                    Unavailable::NoProbe => matched.is_none() && lit.ir.is_none(),
                    Unavailable::NoTemplate
                    | Unavailable::ForeignTag
                    | Unavailable::ForeignRecognizer
                    | Unavailable::WrongWidth
                    | Unavailable::Empty => {
                        matched.is_some_and(|m| m.n_templates == 0) && lit.ir.is_none()
                    }
                    Unavailable::ZeroAdaptedProbe => {
                        matched.is_some_and(|m| m.n_templates == 1 && !m.best.is_finite())
                    }
                    Unavailable::MalformedCalibration => matched.is_some_and(|m| {
                        m.n_templates == 1
                            && m.best.to_bits() == 0.4f32.to_bits()
                            && m.centroid.is_none()
                    }),
                }
        })?;
    }
    Ok(())
}
