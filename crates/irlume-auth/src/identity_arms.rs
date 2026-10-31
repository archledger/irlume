// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The identity arms that turn match scores into a grant, as pure
//! functions. Authentication calls them, and the tests' decision fingerprint
//! runs exactly this code on fixed synthetic inputs and pins the result, so a
//! change to a grant decision has to show up in review (ADR-0039 section 2).
//!
//! Gates (liveness, PAD, the per-user IR floor, scene routing) run before
//! these arms and stay in the engine: they decide whether an attempt may be
//! scored at all, not what a score means.

use super::rgb_primary_grant_admissible;
use irlume_core::fusion::{self, Fusion};
use irlume_vision::align;
#[cfg(test)]
pub(super) mod fingerprint;
#[cfg(test)]
mod thresholds;
#[cfg(test)]
mod witnesses;
#[cfg(test)]
use fingerprint::decision_fingerprint;

/// The identity arm whose comparison consumes the threshold.
#[derive(Clone, Copy, Debug)]
pub(super) enum ThresholdArm {
    Rgb { base: f32 },
    LitFallback { adapter: bool },
    LitCentroid { adapter: bool },
    DarkBest { adapter: bool },
    DarkCentroid { adapter: bool },
}

/// Compute the existing threshold without changing its expression order.
/// `count` is the compared template count for RGB/best-match arms and the
/// enrollment profile count for centroid arms.
pub(super) fn arm_threshold(arm: ThresholdArm, count: usize) -> f32 {
    match arm {
        ThresholdArm::Rgb { base } => irlume_core::scaled_threshold(base, count),
        ThresholdArm::LitFallback { adapter } | ThresholdArm::LitCentroid { adapter } => {
            let base = if adapter {
                irlume_core::IR_ADAPTED_MATCH_THRESHOLD
            } else {
                irlume_core::IR_MATCH_THRESHOLD
            };
            irlume_core::scaled_threshold(base, count) + irlume_core::IR_FALLBACK_MARGIN
        }
        ThresholdArm::DarkBest { adapter } | ThresholdArm::DarkCentroid { adapter } => {
            let base = if adapter {
                irlume_core::IR_ADAPTED_MATCH_THRESHOLD
            } else {
                irlume_core::IR_DARK_MATCH_THRESHOLD
            };
            irlume_core::scaled_threshold(base, count)
        }
    }
}

/// Calibration-aware IR match result (see [`ir_match_in`]).
pub(super) struct IrMatch {
    pub(super) best: f32,
    pub(super) best_who: String,
    pub(super) n_templates: usize,
    /// Best per-profile calibrated-centroid score, only from profiles with a
    /// fitted calibration under a raw pipeline: (score, profile name).
    pub(super) centroid: Option<(f32, String)>,
}

pub(super) struct IdentityThresholds {
    pub(super) best: f32,
    pub(super) centroid: f32,
}

impl IdentityThresholds {
    pub(super) fn new(templates: usize, profiles: usize, adapter: bool) -> Self {
        Self {
            best: arm_threshold(ThresholdArm::DarkBest { adapter }, templates),
            centroid: arm_threshold(ThresholdArm::DarkCentroid { adapter }, profiles),
        }
    }

    pub(super) fn arms(&self, matched: &IrMatch) -> (bool, bool) {
        if matched.n_templates == 0 {
            return (false, false);
        }
        (
            matched.best.is_finite() && matched.best >= self.best,
            matched
                .centroid
                .as_ref()
                .is_some_and(|(score, _)| score.is_finite() && *score >= self.centroid),
        )
    }
}

/// The selected dark-path grant and data from the match that produced it.
#[derive(Clone, Copy, Debug)]
pub(super) enum DarkGrant<'a> {
    Best { score: f32, who: &'a str },
    Centroid { score: f32, who: &'a str },
}

/// Dark identity results, including both arm flags for trace and reporting.
pub(super) struct DarkVerdict<'a> {
    pub(super) thresholds: IdentityThresholds,
    pub(super) best: bool,
    pub(super) centroid: bool,
    pub(super) grant: Option<DarkGrant<'a>>,
}

/// Select best before centroid without performing liveness or PAD checks.
pub(super) fn dark_verdict(matched: &IrMatch, profiles: usize, adapter: bool) -> DarkVerdict<'_> {
    let thresholds = IdentityThresholds::new(matched.n_templates, profiles, adapter);
    let (best, centroid) = thresholds.arms(matched);
    let grant = if best {
        Some(DarkGrant::Best {
            score: matched.best,
            who: &matched.best_who,
        })
    } else if centroid {
        matched
            .centroid
            .as_ref()
            .map(|(score, who)| DarkGrant::Centroid { score: *score, who })
    } else {
        None
    };
    DarkVerdict {
        thresholds,
        best,
        centroid,
        grant,
    }
}

/// IR matching across profiles, calibration-aware. Per profile: when a
/// fitted calibration exists (and no global adapter is loaded), both the
/// probe and that profile's templates are calibrated before scoring, and the
/// calibrated template CENTROID is scored too, the mean-template protocol
/// the 2026-07-15 prototype validated at the BASE threshold (a single mean
/// template carries no best-of-N FAR inflation).
pub(super) fn ir_match_in(
    space: &str,
    embed_space: &str,
    adapter_loaded: bool,
    enr: &irlume_core::storage::Enrollment,
    probe: &[f32],
) -> IrMatch {
    let mut m = IrMatch {
        best: f32::NEG_INFINITY,
        best_who: String::new(),
        n_templates: 0,
        centroid: None,
    };
    // Older custom adapters could store arbitrary vector magnitudes.
    // Normalize both sides in memory; a corrected new probe alone
    // would still let an oversized historical template inflate its dot product.
    let adapted_probe = adapter_loaded
        .then(|| align::normalize_embedding(probe))
        .flatten();
    let scoring_probe = if adapter_loaded {
        adapted_probe.as_deref()
    } else {
        Some(probe)
    };
    for p in &enr.profiles {
        let tmpls: Vec<std::borrow::Cow<'_, [f32]>> = p
            .scans
            .iter()
            .filter_map(|s| {
                // The RECOGNIZER produces the raw IR embedding, so a template
                // from another recognizer is in a foreign space regardless of
                // its adapter tag. This matcher feeds fusion, IR fallback, the
                // calibrated centroid, and dark IR-only auth — all of them
                // grant, so all of them get the same filter RGB matching has.
                if !irlume_core::storage::recognizer_space_matches(
                    s.embed_space.as_deref(),
                    embed_space,
                ) {
                    return None;
                }
                let ir = s.ir.as_ref()?;
                if ir.len() != probe.len() {
                    return None;
                }
                // Before tagging, both raw and adapted IR shipped. An absent
                // tag cannot establish either space, even at the same width.
                if s.ir_space.as_deref() != Some(space) {
                    return None;
                }
                if adapter_loaded {
                    align::normalize_embedding(ir).map(std::borrow::Cow::Owned)
                } else {
                    Some(std::borrow::Cow::Borrowed(ir.as_slice()))
                }
            })
            .collect();
        if tmpls.is_empty() {
            continue;
        }
        m.n_templates += tmpls.len();
        // Diagnostic preflight uses a zero probe to count eligible templates.
        // Retain that count, but invalid adapted probes never produce scores.
        let Some(probe) = scoring_probe else {
            continue;
        };
        // The calibration for THIS recognizer: a profile can hold scans (and
        // calibrations) from several, and applying one model's calibration to
        // another's templates puts uninterpretable numbers into the matcher
        // (#288).
        let calib = if adapter_loaded {
            None
        } else {
            p.calib_for(embed_space)
        };
        let cprobe = calib.and_then(|c| c.apply(probe));
        if let (Some(c), Some(cprobe)) = (calib, &cprobe) {
            let mut centroid = vec![0.0f32; probe.len()];
            let mut used = 0usize;
            for t in &tmpls {
                let Some(ct) = c.apply(t) else { continue };
                let s = align::cosine(cprobe, &ct);
                if s > m.best {
                    m.best = s;
                    m.best_who = p.name.clone();
                }
                for (a, b) in centroid.iter_mut().zip(&ct) {
                    *a += b;
                }
                used += 1;
            }
            if used > 0 {
                let norm = centroid.iter().map(|v| v * v).sum::<f32>().sqrt() + 1e-9;
                for v in centroid.iter_mut() {
                    *v /= norm;
                }
                let cs = align::cosine(cprobe, &centroid);
                if m.centroid.as_ref().is_none_or(|(s, _)| cs > *s) {
                    m.centroid = Some((cs, p.name.clone()));
                }
            }
        } else {
            for t in &tmpls {
                let s = align::cosine(probe, t);
                if s > m.best {
                    m.best = s;
                    m.best_who = p.name.clone();
                }
            }
        }
    }
    m
}

/// Best RGB match over labeled templates: (score, profile name). `>` keeps
/// the first template on a tie.
pub(super) fn best_rgb(probe: &[f32], scans: &[(&str, &str, &[f32])]) -> (f32, String) {
    // Fold over borrowed names and allocate only the winner's String, not
    // one per template.
    let (score, who) = scans
        .iter()
        .map(|(profile, _scan, template)| (irlume_vision::align::cosine(probe, template), *profile))
        .fold(
            (f32::NEG_INFINITY, ""),
            |acc, x| if x.0 > acc.0 { x } else { acc },
        );
    (score, who.to_string())
}

/// The RGB-primary arm: the threshold for `templates` templates of base
/// `base`, and whether `score` grants on it. A sequential-schedule pair
/// never grants on RGB alone (ADR-0014).
pub(super) fn rgb_arm(score: f32, base: f32, templates: usize, sequential: bool) -> (f32, bool) {
    let threshold = arm_threshold(ThresholdArm::Rgb { base }, templates);
    (
        threshold,
        rgb_primary_grant_admissible(score, threshold, sequential),
    )
}

/// Which lit IR arm granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IrArm {
    Fusion,
    Fallback,
    Centroid,
}

/// The lit-path IR arms after the RGB-primary arm did not grant: their
/// values for tracing, and the arm that granted, if any.
#[derive(Clone, Copy, Debug)]
pub(super) struct IrArms {
    pub(super) fusion: Fusion,
    pub(super) fallback_threshold: f32,
    pub(super) centroid_threshold: Option<f32>,
    pub(super) grant: Option<IrArm>,
}

/// The lit-path IR arms for an IR match with templates: brightness-weighted
/// fusion (never for a sequential-schedule pair, ADR-0014), the pure IR
/// fallback, and the calibrated centroid at the base threshold scaled by
/// profile count (ADR-0004).
pub(super) fn lit_ir_arms(
    rgb_score: f32,
    rgb_brightness: f32,
    matched: &IrMatch,
    ir_brightness: f32,
    sequential: bool,
    adapter: bool,
    profiles: usize,
) -> IrArms {
    let ir_score = matched.best;
    let fusion = fusion::fuse(
        fusion::rgb_genuine_prob(rgb_score),
        fusion::rgb_quality_weight(rgb_brightness),
        fusion::ir_genuine_prob(ir_score),
        fusion::ir_quality_weight(true, ir_brightness),
    );
    let fallback_threshold =
        arm_threshold(ThresholdArm::LitFallback { adapter }, matched.n_templates);
    let centroid_threshold = matched
        .centroid
        .as_ref()
        .map(|_| arm_threshold(ThresholdArm::LitCentroid { adapter }, profiles));
    let grant = if fusion.grant && !sequential {
        Some(IrArm::Fusion)
    } else if ir_score >= fallback_threshold {
        Some(IrArm::Fallback)
    } else if matched
        .centroid
        .as_ref()
        .zip(centroid_threshold)
        .is_some_and(|((score, _), threshold)| *score >= threshold)
    {
        Some(IrArm::Centroid)
    } else {
        None
    };
    IrArms {
        fusion,
        fallback_threshold,
        centroid_threshold,
        grant,
    }
}

/// Fixed identity inputs borrowed from one engine.
pub(super) struct DecisionContext<'a> {
    pub(super) embed_space: &'a str,
    pub(super) ir_space: &'a str,
    pub(super) adapter: bool,
    pub(super) rgb_base: f32,
}

/// A lit attempt's identity inputs after its caller's gates passed.
pub(super) struct LitProbe<'a> {
    pub(super) rgb: &'a [f32],
    pub(super) ir: Option<&'a [f32]>,
    pub(super) rgb_brightness: f32,
    pub(super) ir_brightness: f32,
    pub(super) sequential: bool,
}

pub(super) struct RgbDecision {
    pub(super) score: f32,
    pub(super) who: String,
    pub(super) templates: usize,
    pub(super) threshold: f32,
    pub(super) grants: bool,
    pub(super) deferred: bool,
}

pub(super) struct LitIrDecision {
    pub(super) matched: IrMatch,
    pub(super) arms: IrArms,
    pub(super) fusion_deferred: bool,
}

pub(super) struct LitVerdict {
    pub(super) rgb: RgbDecision,
    pub(super) ir: Option<LitIrDecision>,
}

/// A selected lit grant whose profile is borrowed from this verdict.
#[derive(Clone, Copy, Debug)]
pub(super) enum LitGrant<'a> {
    Rgb { score: f32, who: &'a str },
    Fusion { score: f32, who: &'a str },
    Fallback { score: f32, who: &'a str },
    Centroid { score: f32, who: &'a str },
}

impl LitVerdict {
    pub(super) fn grant(&self) -> Option<LitGrant<'_>> {
        if self.rgb.grants {
            return Some(LitGrant::Rgb {
                score: self.rgb.score,
                who: &self.rgb.who,
            });
        }
        let ir = self.ir.as_ref()?;
        Some(match ir.arms.grant? {
            IrArm::Fusion => LitGrant::Fusion {
                score: ir.arms.fusion.prob,
                who: if ir.matched.best >= self.rgb.score {
                    &ir.matched.best_who
                } else {
                    &self.rgb.who
                },
            },
            IrArm::Fallback => LitGrant::Fallback {
                score: ir.matched.best,
                who: &ir.matched.best_who,
            },
            IrArm::Centroid => {
                let (score, who) = ir.matched.centroid.as_ref()?;
                LitGrant::Centroid { score: *score, who }
            }
        })
    }
}

/// Run RGB first; only an ungranted RGB stage can reach IR matching.
pub(super) fn lit_verdict(
    context: &DecisionContext<'_>,
    enrollment: &irlume_core::storage::Enrollment,
    probe: &LitProbe<'_>,
) -> LitVerdict {
    let scans = enrollment.rgb_scans_in(context.embed_space);
    let (score, who) = best_rgb(probe.rgb, &scans);
    let (threshold, grants) = rgb_arm(score, context.rgb_base, scans.len(), probe.sequential);
    let rgb = RgbDecision {
        score,
        who,
        templates: scans.len(),
        threshold,
        grants,
        deferred: probe.sequential && score >= threshold,
    };
    if grants {
        return LitVerdict { rgb, ir: None };
    }
    let ir = probe.ir.and_then(|ir_probe| {
        let matched = ir_match_in(
            context.ir_space,
            context.embed_space,
            context.adapter,
            enrollment,
            ir_probe,
        );
        if matched.n_templates == 0 {
            return None;
        }
        let arms = lit_ir_arms(
            score,
            probe.rgb_brightness,
            &matched,
            probe.ir_brightness,
            probe.sequential,
            context.adapter,
            enrollment.profiles.len(),
        );
        Some(LitIrDecision {
            matched,
            fusion_deferred: arms.fusion.grant && probe.sequential,
            arms,
        })
    });
    LitVerdict { rgb, ir }
}

#[cfg(test)]
/// How often each arm granted and denied over the fingerprint's grid, so a
/// test can show the grid crosses every boundary.
#[derive(Debug, Default)]
pub(super) struct Coverage {
    pub(super) rgb: [usize; 2],
    pub(super) fusion: [usize; 2],
    pub(super) fallback: [usize; 2],
    pub(super) centroid: [usize; 2],
    pub(super) dark_best: [usize; 2],
    pub(super) dark_centroid: [usize; 2],
    pub(super) calibrated: usize,
}

#[cfg(test)]
/// Count a grid outcome for [`Coverage`] and return it as a byte.
fn count(value: bool, counts: &mut [usize; 2]) -> u8 {
    counts[usize::from(value)] += 1;
    u8::from(value)
}

#[cfg(test)]
/// The recognizer space the fingerprint's synthetic templates live in.
const SPACE: &str = "embed:decision-fingerprint";

#[cfg(test)]
/// A unit vector of `dim` components, varied by `seed`.
fn unit(dim: usize, seed: usize) -> Vec<f32> {
    let mut v: Vec<f32> = (0..dim)
        .map(|i| (((i + 1) * (seed * 7 + 3)) % 17) as f32 - 8.0 + 0.5 * seed as f32)
        .collect();
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    for x in &mut v {
        *x /= norm;
    }
    v
}

#[cfg(test)]
fn scan(name: &str, seed: usize, dim: usize) -> irlume_core::storage::FaceScan {
    irlume_core::storage::FaceScan {
        name: name.into(),
        rgb: unit(dim, seed),
        ir: Some(unit(dim, seed + 40)),
        ir_space: Some(irlume_core::storage::IR_RAW_SPACE.into()),
        embed_space: Some(SPACE.into()),
        ir_center_edge_ratio: 0.0,
        ir_brightness: 0.0,
        pitch: 0.0,
        captured_at: None,
    }
}

#[cfg(test)]
/// A synthetic enrollment: one profile with an IR calibration fitted as
/// enrollment fits it, and one without.
fn enrollment(dim: usize) -> irlume_core::storage::Enrollment {
    let mut enrollment = irlume_core::storage::Enrollment::new("fingerprint");
    for (p, calibrated) in [(0usize, true), (1, false)] {
        let scans: Vec<_> = (0..4)
            .map(|s| scan(&format!("p{p}s{s}"), p * 10 + s, dim))
            .collect();
        let mut ir_calibs = std::collections::BTreeMap::new();
        if calibrated {
            let ir: Vec<Vec<f32>> = scans.iter().filter_map(|s| s.ir.clone()).collect();
            let rgb: Vec<Vec<f32>> = scans.iter().map(|s| s.rgb.clone()).collect();
            if let Some(calibration) = irlume_core::calib::fit(&ir, &rgb) {
                ir_calibs.insert(SPACE.to_owned(), calibration);
            }
        }
        enrollment.profiles.push(irlume_core::storage::FaceProfile {
            name: format!("profile{p}"),
            scans,
            ir_calib: None,
            ir_calibs,
        });
    }
    enrollment
}

#[cfg(test)]
/// Run the production decision code over a fixed synthetic grid, writing
/// every output to `out`.
pub(super) fn decision_grid(out: &mut dyn FnMut(&[u8]), coverage: &mut Coverage) {
    let f = |out: &mut dyn FnMut(&[u8]), value: f32| out(&value.to_bits().to_le_bytes());
    // RGB matching over labeled templates.
    let dim = 8;
    let templates: Vec<Vec<f32>> = (0..6).map(|s| unit(dim, s)).collect();
    let labeled: Vec<(&str, &str, &[f32])> = templates
        .iter()
        .enumerate()
        .map(|(i, t)| (["a", "b", "c"][i % 3], "scan", t.as_slice()))
        .collect();
    for probe in 0..4 {
        let (score, who) = best_rgb(&unit(dim, probe + 2), &labeled);
        f(out, score);
        out(who.as_bytes());
    }
    // The IR matcher with and without a fitted calibration, raw space.
    let enrollment = enrollment(dim);
    for probe in 0..6 {
        let matched = ir_match_in(
            irlume_core::storage::IR_RAW_SPACE,
            SPACE,
            false,
            &enrollment,
            &unit(dim, probe + 41),
        );
        f(out, matched.best);
        out(matched.best_who.as_bytes());
        out(&matched.n_templates.to_le_bytes());
        if let Some((score, who)) = &matched.centroid {
            coverage.calibrated += 1;
            f(out, *score);
            out(who.as_bytes());
        }
    }
    let scores = [
        0.30f32, 0.45, 0.52, 0.55, 0.56, 0.58, 0.60, 0.62, 0.635, 0.66, 0.70, 0.80,
    ];
    let counts = [1usize, 2, 3, 5, 10, 30, 90];
    // The RGB-primary arm.
    for &score in &scores {
        for &n in &counts {
            for sequential in [false, true] {
                let (threshold, grants) =
                    rgb_arm(score, irlume_core::RGB_MATCH_THRESHOLD, n, sequential);
                f(out, threshold);
                out(&[count(grants, &mut coverage.rgb)]);
            }
        }
    }
    // The lit IR arms.
    for &rgb in &[0.30f32, 0.45, 0.52, 0.56, 0.70] {
        for &ir in &scores {
            for centroid in [None, Some(0.55f32), Some(0.62), Some(0.70)] {
                for &n in &[1usize, 10, 90] {
                    let matched = IrMatch {
                        best: ir,
                        best_who: "p".into(),
                        n_templates: n,
                        centroid: centroid.map(|c| (c, "c".to_owned())),
                    };
                    for &rgb_brightness in &[20.0f32, 60.0, 120.0, 200.0] {
                        for &ir_brightness in &[20.0f32, 60.0, 140.0] {
                            for sequential in [false, true] {
                                for adapter in [false, true] {
                                    for profiles in [1usize, 3] {
                                        let arms = lit_ir_arms(
                                            rgb,
                                            rgb_brightness,
                                            &matched,
                                            ir_brightness,
                                            sequential,
                                            adapter,
                                            profiles,
                                        );
                                        f(out, arms.fusion.prob);
                                        f(out, arms.fusion.p_rgb);
                                        f(out, arms.fusion.p_ir);
                                        f(out, arms.fallback_threshold);
                                        f(out, arms.centroid_threshold.unwrap_or(f32::NAN));
                                        let arm = arms.grant;
                                        out(&[
                                            u8::from(arms.fusion.grant),
                                            count(arm == Some(IrArm::Fusion), &mut coverage.fusion),
                                            count(
                                                arm == Some(IrArm::Fallback),
                                                &mut coverage.fallback,
                                            ),
                                            count(
                                                arm == Some(IrArm::Centroid),
                                                &mut coverage.centroid,
                                            ),
                                        ]);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // The dark path's IR arms.
    for &ir in &scores {
        for centroid in [None, Some(0.62f32), Some(0.70)] {
            for &n in &counts {
                for profiles in [1usize, 3] {
                    for adapter in [false, true] {
                        let matched = IrMatch {
                            best: ir,
                            best_who: "p".into(),
                            n_templates: n,
                            centroid: centroid.map(|c| (c, "c".to_owned())),
                        };
                        let thresholds = IdentityThresholds::new(n, profiles, adapter);
                        let (best, centroid) = thresholds.arms(&matched);
                        f(out, thresholds.best);
                        f(out, thresholds.centroid);
                        out(&[
                            count(best, &mut coverage.dark_best),
                            count(centroid, &mut coverage.dark_centroid),
                        ]);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "identity_arms/lit_tests.rs"]
mod lit_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dark_verdict_preserves_priority_flags_and_identity_data() {
        for adapter in [false, true] {
            for templates in [0, 1, 30, 90, usize::MAX] {
                for profiles in [0, 1, 3, 90] {
                    let thresholds = IdentityThresholds::new(templates, profiles, adapter);
                    for best in [
                        f32::NEG_INFINITY,
                        -0.0,
                        thresholds.best.next_down(),
                        thresholds.best,
                        thresholds.best.next_up(),
                        f32::INFINITY,
                        f32::NAN,
                    ] {
                        for centroid in [
                            None,
                            Some(f32::NEG_INFINITY),
                            Some(thresholds.centroid.next_down()),
                            Some(thresholds.centroid),
                            Some(thresholds.centroid.next_up()),
                            Some(f32::INFINITY),
                            Some(f32::NAN),
                        ] {
                            let matched = IrMatch {
                                best,
                                best_who: "best-profile".into(),
                                n_templates: templates,
                                centroid: centroid.map(|score| (score, "centroid-profile".into())),
                            };
                            let best_passes =
                                templates > 0 && best.is_finite() && best >= thresholds.best;
                            let centroid_passes = templates > 0
                                && centroid.is_some_and(|score| {
                                    score.is_finite() && score >= thresholds.centroid
                                });
                            let expected = if best_passes {
                                Some((0, best.to_bits(), "best-profile"))
                            } else if centroid_passes {
                                centroid.map(|score| (1, score.to_bits(), "centroid-profile"))
                            } else {
                                None
                            };
                            let verdict = dark_verdict(&matched, profiles, adapter);
                            assert_eq!(
                                verdict.thresholds.best.to_bits(),
                                thresholds.best.to_bits()
                            );
                            assert_eq!(
                                verdict.thresholds.centroid.to_bits(),
                                thresholds.centroid.to_bits()
                            );
                            assert_eq!(
                                (verdict.best, verdict.centroid),
                                (best_passes, centroid_passes)
                            );
                            let actual = verdict.grant.map(|grant| match grant {
                                DarkGrant::Best { score, who } => (0, score.to_bits(), who),
                                DarkGrant::Centroid { score, who } => (1, score.to_bits(), who),
                            });
                            assert_eq!(actual, expected, "adapter={adapter} templates={templates} profiles={profiles} best={best:?} centroid={centroid:?}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn threshold_roles_preserve_the_existing_expression_bits() {
        let counts = (0usize..=256)
            .chain((0..usize::BITS).map(|shift| 1usize << shift))
            .chain([usize::MAX]);
        for count in counts {
            for base in [
                -1.0,
                -0.0,
                0.0,
                0.55,
                1.0,
                f32::from_bits(1),
                f32::from_bits(0x7fc1_2345),
                f32::NEG_INFINITY,
                f32::INFINITY,
            ] {
                let expected = irlume_core::scaled_threshold(base, count);
                assert_eq!(
                    arm_threshold(ThresholdArm::Rgb { base }, count).to_bits(),
                    expected.to_bits(),
                    "RGB count={count}, base={:08x}",
                    base.to_bits()
                );
            }
            for adapter in [false, true] {
                let lit_base = if adapter {
                    irlume_core::IR_ADAPTED_MATCH_THRESHOLD
                } else {
                    irlume_core::IR_MATCH_THRESHOLD
                };
                let dark_base = if adapter {
                    irlume_core::IR_ADAPTED_MATCH_THRESHOLD
                } else {
                    irlume_core::IR_DARK_MATCH_THRESHOLD
                };
                for (arm, expected) in [
                    (
                        ThresholdArm::LitFallback { adapter },
                        irlume_core::scaled_threshold(lit_base, count)
                            + irlume_core::IR_FALLBACK_MARGIN,
                    ),
                    (
                        ThresholdArm::LitCentroid { adapter },
                        irlume_core::scaled_threshold(lit_base, count)
                            + irlume_core::IR_FALLBACK_MARGIN,
                    ),
                    (
                        ThresholdArm::DarkBest { adapter },
                        irlume_core::scaled_threshold(dark_base, count),
                    ),
                    (
                        ThresholdArm::DarkCentroid { adapter },
                        irlume_core::scaled_threshold(dark_base, count),
                    ),
                ] {
                    assert_eq!(
                        arm_threshold(arm, count).to_bits(),
                        expected.to_bits(),
                        "{arm:?}, count={count}"
                    );
                }
            }
        }
    }

    fn matched(best: f32, n_templates: usize, centroid: Option<f32>) -> IrMatch {
        IrMatch {
            best,
            best_who: "p".into(),
            n_templates,
            centroid: centroid.map(|score| (score, "c".to_owned())),
        }
    }

    // Pin the pre-refactor grid from 9954e65a. Its stream contains native-size
    // counts and libm results; this baseline was checked on GNU/Linux x86_64
    // with Rust 1.88 (Ubuntu 24.04 and Fedora 44) and stable 1.96 (Fedora 44).
    // This preserves the existing grid.
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
    #[test]
    fn the_existing_arm_grid_fingerprint_matches_the_recorded_reference() {
        assert_eq!(
            fingerprint::arm_grid_fingerprint(),
            "16edf23e552e480c8a92d99247078c676c989f576b3213e6afaa4cda6a12796d",
            "preserve the existing arm grid when expanding the decision fingerprint"
        );
    }

    #[test]
    fn the_decision_fingerprint_is_stable_and_crosses_every_boundary() {
        assert_eq!(decision_fingerprint(), decision_fingerprint());
        assert_eq!(decision_fingerprint().len(), 64);
        let mut coverage = Coverage::default();
        decision_grid(&mut |_: &[u8]| {}, &mut coverage);
        for (arm, counts) in [
            ("rgb", coverage.rgb),
            ("fusion", coverage.fusion),
            ("fallback", coverage.fallback),
            ("centroid", coverage.centroid),
            ("dark best", coverage.dark_best),
            ("dark centroid", coverage.dark_centroid),
        ] {
            assert!(counts[0] > 0 && counts[1] > 0, "{arm} never {counts:?}");
        }
        assert!(coverage.calibrated > 0, "the calibrated IR matcher ran");
    }

    #[test]
    fn the_rgb_arm_is_the_scaled_threshold_and_never_grants_a_sequential_pair_alone() {
        let base = irlume_core::RGB_MATCH_THRESHOLD;
        for n in [1, 2, 10, 90] {
            let (threshold, _) = rgb_arm(0.0, base, n, false);
            assert_eq!(threshold, irlume_core::scaled_threshold(base, n));
        }
        assert!(rgb_arm(0.95, base, 1, false).1);
        assert!(!rgb_arm(0.95, base, 1, true).1, "ADR-0014");
        assert!(!rgb_arm(base - 0.01, base, 1, false).1);
    }

    #[test]
    fn the_lit_ir_arms_grant_in_order_and_a_sequential_pair_never_fuses() {
        // Fusion first, unless the pair is sequential.
        let strong = matched(0.70, 1, None);
        let fused = lit_ir_arms(0.52, 120.0, &strong, 60.0, false, false, 1);
        assert_eq!(fused.grant, Some(IrArm::Fusion));
        let sequential = lit_ir_arms(0.52, 120.0, &strong, 60.0, true, false, 1);
        assert!(sequential.fusion.grant);
        assert_eq!(
            sequential.grant,
            Some(IrArm::Fallback),
            "IR identity arms only"
        );
        // A weak IR score: no fallback; the centroid decides alone.
        let weak = matched(0.40, 10, Some(0.70));
        let arms = lit_ir_arms(0.30, 120.0, &weak, 60.0, true, false, 1);
        assert_eq!(arms.grant, Some(IrArm::Centroid));
        assert_eq!(
            arms.centroid_threshold,
            Some(
                irlume_core::scaled_threshold(irlume_core::IR_MATCH_THRESHOLD, 1)
                    + irlume_core::IR_FALLBACK_MARGIN
            )
        );
        let none = lit_ir_arms(0.30, 120.0, &matched(0.40, 10, None), 60.0, true, false, 1);
        assert_eq!(none.grant, None);
        assert_eq!(none.centroid_threshold, None);
    }
}
