// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Matching, template storage, and TPM-bound secret release.
//!
//! Decision rule (NIST SP 800-63B-4 aligned): grant only if the liveness gate
//! says Live AND the best cosine >= a FIXED threshold (0.55). That threshold
//! clears FMR <= 1e-4 per demographic group on FairFace, but unconstrained
//! real-world FAR is higher (2.0e-3 @ 0.55 on LFW); the mandatory password
//! fallback bounds the residual. See the `RGB` threshold constant below for the
//! measured numbers. Threshold is NOT ported from linhello (0.60): AuraFace's
//! score scale differs; derive it from a genuine/impostor ROC on real data.
//!
//! Storage: never store a raw recoverable face image. Store L2-normalized
//! embeddings (zeroized after use). The unlock SECRET (e.g. the login password
//! or a random release token) is SEALED IN THE TPM, gated by PCR policy, and
//! released only on a successful live+match, not the template itself.

pub mod biopolicy;
pub mod calib;
pub mod crypto;
pub mod envelope;
pub mod fusion;
pub mod keyring;
pub mod kwallet;
pub mod pad;
pub mod pcrsig;
pub mod policy;
pub mod recovery;
pub mod storage;
pub mod template_key;
pub mod tpm;
pub mod tpm_pcrlock;

/// A per-process-unique `/tmp` path for a test that writes to a state dir. A
/// fixed path collides across users on a shared host: a CI run as one user
/// leaves the dir owned by them, so a later run as a different user gets EACCES
/// on remove/create (observed on a self-hosted runner box). The process id
/// makes each run's dir distinct; ENV_LOCK still serializes within a process.
#[cfg(test)]
pub(crate) fn test_tmp_dir(name: &str) -> String {
    use std::os::unix::fs::MetadataExt;
    use std::sync::OnceLock;

    // Identity = uid + boot id + pid + process start time (#325 review).
    // uid alone separates CI users; pid alone is not unique over time because
    // PIDs wrap at kernel.pid_max, and uid+pid still collides with a stale
    // directory left by an earlier run of the SAME user that reused the pid.
    // The boot id changes across reboots and the start time (field 22 of
    // /proc/self/stat, in clock ticks since boot) distinguishes two processes
    // that shared a pid within one boot, so a surviving directory can only
    // belong to a process that is still alive.
    static IDENTITY: OnceLock<String> = OnceLock::new();
    let identity = IDENTITY.get_or_init(|| {
        let uid = std::fs::metadata("/proc/self")
            .expect("stat /proc/self for the test temp-dir uid")
            .uid();
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .expect("read /proc/sys/kernel/random/boot_id");
        let stat = std::fs::read_to_string("/proc/self/stat")
            .expect("read /proc/self/stat for the process start time");
        // Field 22 counting from 1, but comm (field 2) may contain spaces, so
        // parse after the closing paren rather than splitting the whole line.
        let after_comm = stat
            .rfind(')')
            .map(|i| &stat[i + 1..])
            .expect("/proc/self/stat has no comm field");
        let starttime = after_comm
            .split_whitespace()
            .nth(19)
            .expect("/proc/self/stat has no starttime field");
        format!(
            "u{uid}-b{}-p{}-t{starttime}",
            boot.trim().replace('-', "").get(..8).unwrap_or("00000000"),
            std::process::id(),
        )
    });
    format!("/tmp/irlume-test-{name}-{identity}")
}

/// RGB (visible-light) match threshold. Measured FAR: real faces (LFW, 13,233
/// images, 87M impostor pairs, same pipeline as production) give FAR 2.3e-3 @
/// 0.50 and 2.0e-3 @ 0.55; synthetic (SFHQ, 112M pairs) 9.8e-5 @ 0.50 (cleaner
/// than unconstrained real photos). **Set to 0.55** for demographic headroom:
/// FairFace per-group analysis showed 0.50 only clears FMR≤1e-4 for the best
/// group; ~0.55+ tightens every group (see docs/FAIRNESS.md), and because live
/// genuine sits at min 0.71 / mean 0.85, so 0.55 keeps a wide accept margin (no
/// added false-rejects). Unconstrained real-world FAR stays well above Windows
/// Hello's stated 1e-5 bar; the mandatory password fallback bounds the residual.
/// Do NOT assume buffalo_l's 0.60; AuraFace scale differs.
pub const RGB_MATCH_THRESHOLD: f32 = 0.55;

/// IR-mode (dark) match threshold base, HIGHER than RGB because
/// AuraFace-on-IR is less discriminative. Benchmarked on the FULL CBSR NIR
/// dataset (real 850nm, 197 people, 3940 faces, 7.72M impostor pairs):
/// genuine mean 0.855, impostor MAX 0.900 (genuine/impostor OVERLAP), EER
/// ≈0.8% @0.495. FAR/FRR: 0.55→ 1.3e-3/1.7%, 0.60→2.7e-4/3.0%, NIST FAR≤1e-4
/// only @0.635 (FRR 4.6%). This base now serves the DIM-LIGHT IR FALLBACK
/// (as base + [`IR_FALLBACK_MARGIN`], i.e. 0.60) and the calibration bench;
/// the PURE-DARK path uses the stricter [`IR_DARK_MATCH_THRESHOLD`]
/// (ADR-0016). Live genuine IR ~0.65 sits in the overlap zone, so raising
/// the live dark bar beyond 0.60 waits on the fleet dark-session
/// measurement.
pub const IR_MATCH_THRESHOLD: f32 = 0.55;

/// The PURE-DARK (IR-only) authentication threshold, SecureDark v1
/// (ADR-0016). Higher than [`IR_MATCH_THRESHOLD`] because a pure-dark grant
/// carries NO RGB evidence at all — no co-location, no RGB recognition, no
/// RGB PAD — so the IR cosine alone must clear a stricter statistical bar.
///
/// Evidence (same CBSR NIR benchmark as above): 0.55 → FAR 1.3e-3 / FRR
/// 1.7%; **0.60 → FAR 2.7e-4 / FRR 3.0%** — a ~5x impostor-bar tightening
/// for +1.3% false rejects. The old pure-dark bar was a consistency
/// inversion: the DIM-LIGHT fallback (which at least SAW an RGB face) demanded
/// base+0.60 while pure dark (strictly less evidence) granted at 0.55; this
/// constant aligns the two at the stricter end.
///
/// What this threshold does NOT do: stop the life-size print species. ADR-0002
/// measured the vinyl banner of the enrolled user at IR cosine 0.650 — above
/// 0.60 and above even the 0.635 FAR≤1e-4 point — so prints are FLIR PAD +
/// IR physics + per-user center/edge floor's job, never the threshold's.
///
/// 0.635 (FAR ≤1e-4, FRR 4.6% on CBSR) is the measured next rung, NOT
/// shipped: the threshold doc's live observation ("genuine IR in the overlap
/// zone") means the live dark-session genuine distribution must be measured
/// on the fleet before the bar goes there (ADR-0016's open measurement).
pub const IR_DARK_MATCH_THRESHOLD: f32 = 0.60;

/// Match threshold for ADAPTED IR embeddings (when an IR adapter is loaded).
/// No adapter ships by default (retired 2026-07-15, ADR-0004: its training data
/// was research-only, and it worsened unseen identities); the default IR path is
/// raw AuraFace plus per-enrollment calibration. This threshold applies only when
/// a user supplies their own 512→512 adapter via `--adapter` / `IRLUME_IR_ADAPTER`.
/// 0.40 corresponds to FAR ~1e-4 on the CBSR+Oulu academic distribution (FAR≈1e-3
/// at 0.354, FAR≈1e-4 at 0.410) and MUST be re-validated on the live camera at
/// re-enroll, since a different adapter is a different cosine space.
pub const IR_ADAPTED_MATCH_THRESHOLD: f32 = 0.40;

/// Extra margin added to the IR threshold when IR is used as a DIM-LIGHT FALLBACK
/// after the RGB match already missed (Secure tier). The fallback grants a second
/// chance via the IR-emitter-lit face when ambient light is too low for RGB
/// recognition, but a second modality adds false-accept risk, so demand a
/// clearer IR match than the pure-dark path. Cross-spectral adaptive-fusion knob;
/// re-tune against live genuine IR-fallback margins.
pub const IR_FALLBACK_MARGIN: f32 = 0.05;

/// Threshold scaling per doubling of the template count. Matching takes the
/// MAX cosine over a profile's N templates, which inflates the false-accept rate
/// roughly linearly in N (union bound: P(any of N exceeds) ≈ N·p). Windows Hello
/// raises its threshold as more *users* enroll for the same reason; irlume is
/// 1:1 (PAM supplies the claimed user), so the equivalent compensation scales
/// with the number of *templates compared against*. Calibration (LFW): ~+0.05
/// cosine halves the impostor tail, so full compensation would be 0.05·log2(N),
/// but that approaches the genuine floor (~0.71) and would add false-rejects, so
/// this PARTIAL step (0.015·log2(N)) gently raises the bar while preserving the
/// accept margin. A heuristic; tune with a per-N impostor ROC.
pub const TEMPLATE_SCALE_STEP: f32 = 0.015;
/// Max upward adjustment (cosine), a safety cap kept well below the genuine
/// floor so scaling can never lock out a legitimate user.
pub const TEMPLATE_SCALE_MAX_BUMP: f32 = 0.10;

/// Effective match threshold for a profile holding `n_templates`, raised from
/// `base` to hold the false-accept rate roughly constant as templates accumulate
/// (max-over-N inflates FAR ~linearly). Monotonic in `n_templates`, capped at
/// `base + TEMPLATE_SCALE_MAX_BUMP`. `n_templates ≤ 1` returns `base` unchanged.
pub fn scaled_threshold(base: f32, n_templates: usize) -> f32 {
    if n_templates <= 1 {
        return base;
    }
    let bump = (TEMPLATE_SCALE_STEP * (n_templates as f32).log2()).min(TEMPLATE_SCALE_MAX_BUMP);
    base + bump
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_scales_monotonically_and_caps() {
        // One template (or none): unchanged.
        assert_eq!(scaled_threshold(0.55, 1), 0.55);
        assert_eq!(scaled_threshold(0.55, 0), 0.55);
        // Rises with template count.
        let t2 = scaled_threshold(0.55, 2);
        let t5 = scaled_threshold(0.55, 5);
        let t10 = scaled_threshold(0.55, 10);
        assert!(t2 > 0.55 && t5 > t2 && t10 > t5, "{t2} {t5} {t10}");
        // Stays below the genuine floor (~0.71) for realistic counts.
        assert!(t10 < 0.65, "10-template thr {t10} too high");
        // Capped: even an absurd count can't exceed base + MAX_BUMP.
        assert!(scaled_threshold(0.55, 100_000) <= 0.55 + TEMPLATE_SCALE_MAX_BUMP + 1e-6);
    }
}

/// One crate-wide lock for tests that mutate process-global environment
/// variables (IRLUME_KEYRING_DIR, IRLUME_TEMPLATE_KEY_DIR, ...): env is shared
/// across the whole test binary, so per-module locks cannot stop cross-module
/// races when the parallel runner interleaves them.
#[cfg(test)]
pub(crate) mod testenv {
    pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
}
