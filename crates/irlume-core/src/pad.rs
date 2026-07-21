// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! ISO/IEC 30107-3 presentation-attack-detection (PAD) metrics.
//!
//! Pure, hardware-free aggregation of labeled presentation trials into the
//! standard PAD error rates, so the `irlume padreport` tool (and its tests) share
//! one authoritative implementation. Definitions follow ISO/IEC 30107-3:
//!
//!  * **APCER** (Attack Presentation Classification Error Rate): the fraction of
//!    *attack* presentations classified as bona fide, computed **per PAI species**
//!    and reported at the **worst-case (max) species**, never averaged across
//!    species. This is the number that says "did a spoof get in".
//!  * **BPCER** (Bona-fide Presentation Classification Error Rate): the fraction
//!    of *bona-fide* presentations classified as attacks (a live user wrongly
//!    rejected).
//!  * **Non-response**: presentations that yielded no decision (our `Uncertain`
//!    verdict: "re-present / face the camera"). ISO reports these separately from
//!    APCER/BPCER; we keep them in the denominator (so they lower APCER, since an
//!    Uncertain attack did NOT succeed) but surface the rate on its own so a
//!    species whose attacks merely stall (and could be retried) is visible.
//!  * **ACER** = (APCER_worst + BPCER) / 2, deprecated by newer ISO revisions but
//!    still the iBeta-style single headline; reported for continuity only.
//!
//! Every rate carries a **Clopper-Pearson exact 95% binomial confidence interval**.
//! With the small sample sizes a home self-test can realistically capture, the
//! point estimate alone is misleading (0/20 attacks accepted is NOT "0% APCER";
//! it is "APCER ≤ 16.8% at 95% confidence"). The interval keeps the claim honest.

/// Ground-truth label of a presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    BonaFide,
    Attack,
}

/// How the liveness gate classified a presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Classified as a genuine live face (`Verdict::Live`).
    Accepted,
    /// Classified as a spoof (`Verdict::Spoof`).
    Rejected,
    /// No decision; asked to re-present (`Verdict::Uncertain`).
    NonResponse,
}

/// One labeled presentation and how the gate handled it.
#[derive(Debug, Clone)]
pub struct Trial {
    pub species: String,
    pub label: Label,
    pub outcome: Outcome,
    /// Cue(s) that rejected this presentation (empty unless `Rejected`), used for
    /// per-species attribution so hardening targets the cue that actually catches
    /// (or fails to catch) each attack species.
    pub caught: Vec<String>,
}

/// A count-based rate with an exact 95% confidence interval.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rate {
    pub num: usize,
    pub den: usize,
    /// Point estimate `num/den` (NaN when `den == 0`).
    pub p: f64,
    /// Clopper-Pearson 95% lower/upper bounds.
    pub lo: f64,
    pub hi: f64,
}

impl Rate {
    pub fn new(num: usize, den: usize) -> Self {
        let (lo, hi) = clopper_pearson(num, den, 0.05);
        let p = if den == 0 {
            f64::NAN
        } else {
            num as f64 / den as f64
        };
        Self {
            num,
            den,
            p,
            lo,
            hi,
        }
    }
}

/// Per-PAI-species attack results.
#[derive(Debug, Clone)]
pub struct SpeciesReport {
    pub species: String,
    pub n_attacks: usize,
    /// APCER: attacks classified as bona fide, over all attacks of this species.
    pub apcer: Rate,
    /// Attacks that stalled at `Uncertain` (non-response), over all attacks.
    pub nonresponse: Rate,
    /// Among *rejected* attacks, how many each cue caught (descending). An attack
    /// may fail several cues; the first hard-gate failure is what's recorded.
    pub cue_hits: Vec<(String, usize)>,
}

/// The full PAD self-test report.
#[derive(Debug, Clone)]
pub struct PadReport {
    pub species: Vec<SpeciesReport>,
    /// Worst-case (species, APCER point estimate), the ISO headline. `None` when
    /// there were no attack presentations.
    pub worst_apcer: Option<(String, f64)>,
    pub n_attacks: usize,
    pub n_bonafide: usize,
    /// BPCER over all bona-fide presentations.
    pub bpcer: Rate,
    /// Bona-fide presentations that stalled at `Uncertain` (non-response).
    pub bonafide_nonresponse: Rate,
    /// ACER = (worst-case APCER + BPCER) / 2. `None` when no attacks were tested.
    pub acer: Option<f64>,
}

/// Aggregate labeled trials into the ISO/IEC 30107-3 report.
pub fn analyze(trials: &[Trial]) -> PadReport {
    // Group attack trials by species, preserving first-seen order.
    let mut order: Vec<String> = Vec::new();
    let mut species: std::collections::HashMap<String, Vec<&Trial>> =
        std::collections::HashMap::new();
    for t in trials.iter().filter(|t| t.label == Label::Attack) {
        if !species.contains_key(&t.species) {
            order.push(t.species.clone());
        }
        species.entry(t.species.clone()).or_default().push(t);
    }

    let mut reports = Vec::new();
    for name in &order {
        let ts = &species[name];
        let n = ts.len();
        let accepted = ts.iter().filter(|t| t.outcome == Outcome::Accepted).count();
        let nonresp = ts
            .iter()
            .filter(|t| t.outcome == Outcome::NonResponse)
            .count();
        let mut hits: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for t in ts.iter().filter(|t| t.outcome == Outcome::Rejected) {
            for c in &t.caught {
                *hits.entry(c.clone()).or_default() += 1;
            }
        }
        let mut cue_hits: Vec<(String, usize)> = hits.into_iter().collect();
        // Descending by count, then name for deterministic ties.
        cue_hits.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        reports.push(SpeciesReport {
            species: name.clone(),
            n_attacks: n,
            apcer: Rate::new(accepted, n),
            nonresponse: Rate::new(nonresp, n),
            cue_hits,
        });
    }

    let worst_apcer = reports
        .iter()
        .filter(|r| r.n_attacks > 0)
        .max_by(|a, b| {
            a.apcer
                .p
                .partial_cmp(&b.apcer.p)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|r| (r.species.clone(), r.apcer.p));

    let bonafide: Vec<&Trial> = trials
        .iter()
        .filter(|t| t.label == Label::BonaFide)
        .collect();
    let bf_n = bonafide.len();
    let bf_rejected = bonafide
        .iter()
        .filter(|t| t.outcome == Outcome::Rejected)
        .count();
    let bf_nonresp = bonafide
        .iter()
        .filter(|t| t.outcome == Outcome::NonResponse)
        .count();
    let bpcer = Rate::new(bf_rejected, bf_n);

    let acer = worst_apcer.as_ref().map(|(_, ap)| {
        let bp = if bf_n == 0 { 0.0 } else { bpcer.p };
        (ap + bp) / 2.0
    });

    PadReport {
        n_attacks: trials.iter().filter(|t| t.label == Label::Attack).count(),
        n_bonafide: bf_n,
        species: reports,
        worst_apcer,
        bpcer,
        bonafide_nonresponse: Rate::new(bf_nonresp, bf_n),
        acer,
    }
}

// ---------------------------------------------------------------------------
// Clopper-Pearson exact binomial confidence interval.
//
// Inverts the regularized incomplete beta function I_x(a,b):
//   lo = 0            if x == 0 else BetaInv(alpha/2;   x,   n-x+1)
//   hi = 1            if x == n else BetaInv(1-alpha/2; x+1, n-x)
// ---------------------------------------------------------------------------

/// Clopper-Pearson two-sided interval for `x` successes in `n` trials at level
/// `alpha` (e.g. 0.05 → 95%). Returns `(0.0, 1.0)` when `n == 0`.
pub fn clopper_pearson(x: usize, n: usize, alpha: f64) -> (f64, f64) {
    if n == 0 {
        return (0.0, 1.0);
    }
    let (x, n) = (x as f64, n as f64);
    let lo = if x == 0.0 {
        0.0
    } else {
        beta_inv(alpha / 2.0, x, n - x + 1.0)
    };
    let hi = if x == n {
        1.0
    } else {
        beta_inv(1.0 - alpha / 2.0, x + 1.0, n - x)
    };
    (lo, hi)
}

/// Inverse of the regularized incomplete beta `I_y(a,b) = p` by bisection. `I` is
/// monotone increasing in `y`, so bisection converges reliably; 100 steps give
/// ~2^-100 precision, far tighter than we report.
fn beta_inv(p: f64, a: f64, b: f64) -> f64 {
    let (mut lo, mut hi) = (0.0f64, 1.0f64);
    for _ in 0..100 {
        let mid = 0.5 * (lo + hi);
        if betai(a, b, mid) < p {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    0.5 * (lo + hi)
}

/// Regularized incomplete beta function `I_x(a,b)` (Numerical Recipes form).
fn betai(a: f64, b: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let bt = (ln_gamma(a + b) - ln_gamma(a) - ln_gamma(b) + a * x.ln() + b * (1.0 - x).ln()).exp();
    if x < (a + 1.0) / (a + b + 2.0) {
        bt * betacf(a, b, x) / a
    } else {
        1.0 - bt * betacf(b, a, 1.0 - x) / b
    }
}

/// Continued-fraction evaluation used by `betai` (Lentz's method).
fn betacf(a: f64, b: f64, x: f64) -> f64 {
    const MAXIT: usize = 300;
    const EPS: f64 = 3.0e-14;
    const FPMIN: f64 = 1.0e-300;
    let qab = a + b;
    let qap = a + 1.0;
    let qam = a - 1.0;
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < FPMIN {
        d = FPMIN;
    }
    d = 1.0 / d;
    let mut h = d;
    for m in 1..=MAXIT {
        let m = m as f64;
        let m2 = 2.0 * m;
        let mut aa = m * (b - m) * x / ((qam + m2) * (a + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        h *= d * c;
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;
        if (del - 1.0).abs() < EPS {
            break;
        }
    }
    h
}

/// Natural log of the gamma function (Lanczos g=7, n=9). Our arguments are always
/// ≥ 1, so no reflection formula is needed.
fn ln_gamma(x: f64) -> f64 {
    const C: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_1,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    let x = x - 1.0;
    let t = x + 7.5;
    let mut a = C[0];
    for (i, &c) in C.iter().enumerate().skip(1) {
        a += c / (x + i as f64);
    }
    0.5 * (2.0 * std::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + a.ln()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    #[test]
    fn clopper_pearson_matches_known_values() {
        // Reference values (R binom.test / scipy.stats.beta), 95% two-sided.
        let (lo, hi) = clopper_pearson(0, 10, 0.05);
        assert!(approx(lo, 0.0, 1e-9), "lo={lo}");
        assert!(approx(hi, 0.308_50, 1e-4), "hi={hi}");

        let (lo, hi) = clopper_pearson(0, 20, 0.05);
        assert!(approx(lo, 0.0, 1e-9));
        assert!(approx(hi, 0.168_43, 1e-4), "hi={hi}");

        let (lo, hi) = clopper_pearson(1, 20, 0.05);
        assert!(approx(lo, 0.001_26, 1e-4), "lo={lo}");
        assert!(approx(hi, 0.248_73, 1e-4), "hi={hi}");

        let (lo, hi) = clopper_pearson(5, 20, 0.05);
        assert!(approx(lo, 0.086_57, 1e-4), "lo={lo}");
        assert!(approx(hi, 0.491_04, 1e-4), "hi={hi}");
    }

    #[test]
    fn clopper_pearson_full_success_and_empty() {
        assert_eq!(clopper_pearson(10, 10, 0.05).1, 1.0);
        assert_eq!(clopper_pearson(0, 0, 0.05), (0.0, 1.0));
    }

    fn attack(species: &str, outcome: Outcome, caught: &[&str]) -> Trial {
        Trial {
            species: species.into(),
            label: Label::Attack,
            outcome,
            caught: caught.iter().map(|s| s.to_string()).collect(),
        }
    }
    fn bonafide(outcome: Outcome) -> Trial {
        Trial {
            species: "bonafide".into(),
            label: Label::BonaFide,
            outcome,
            caught: vec![],
        }
    }

    #[test]
    fn perfect_gate_reports_zero_apcer_and_bpcer() {
        let mut trials = vec![];
        for _ in 0..20 {
            trials.push(attack("phone_replay", Outcome::Rejected, &["face_in_ir"]));
        }
        for _ in 0..10 {
            trials.push(bonafide(Outcome::Accepted));
        }
        let r = analyze(&trials);
        assert_eq!(r.worst_apcer, Some(("phone_replay".into(), 0.0)));
        assert_eq!(r.bpcer.num, 0);
        assert!(approx(r.acer.unwrap(), 0.0, 1e-12));
        // But the CI is honest: 0/20 does not prove 0%.
        assert!(r.species[0].apcer.hi > 0.16);
        // Attribution points at the IR-face cue.
        assert_eq!(r.species[0].cue_hits, vec![("face_in_ir".into(), 20)]);
    }

    #[test]
    fn worst_case_is_reported_not_average() {
        let mut trials = vec![];
        // Species A: airtight.
        for _ in 0..10 {
            trials.push(attack("A", Outcome::Rejected, &["depth_ok"]));
        }
        // Species B: 3/10 slipped through as bona fide.
        for _ in 0..7 {
            trials.push(attack("B", Outcome::Rejected, &["depth_ok"]));
        }
        for _ in 0..3 {
            trials.push(attack("B", Outcome::Accepted, &[]));
        }
        let r = analyze(&trials);
        // Worst-case is B's 0.30, not the (0.0+0.3)/2 average.
        let (sp, ap) = r.worst_apcer.clone().unwrap();
        assert_eq!(sp, "B");
        assert!(approx(ap, 0.30, 1e-12));
    }

    #[test]
    fn nonresponse_is_not_an_apcer_success() {
        // An attack that stalls at Uncertain is NOT accepted -> APCER 0, but the
        // non-response rate is surfaced so the retry exposure is visible.
        let mut trials = vec![];
        for _ in 0..10 {
            trials.push(attack("cutout", Outcome::NonResponse, &[]));
        }
        let r = analyze(&trials);
        assert_eq!(r.species[0].apcer.num, 0);
        assert_eq!(r.species[0].nonresponse.num, 10);
        assert!(approx(r.species[0].nonresponse.p, 1.0, 1e-12));
    }

    #[test]
    fn bpcer_counts_bonafide_rejections() {
        let mut trials = vec![bonafide(Outcome::Accepted); 8];
        trials.push(bonafide(Outcome::Rejected)); // one live user wrongly flagged
        trials.push(bonafide(Outcome::NonResponse)); // one stalled (non-response)
        let r = analyze(&trials);
        assert_eq!(r.bpcer.num, 1);
        assert_eq!(r.bpcer.den, 10);
        assert_eq!(r.bonafide_nonresponse.num, 1);
    }
}
