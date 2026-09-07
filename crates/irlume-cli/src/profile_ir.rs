//! Shared profile IR guidance for the CLI and Faces view.
use irlume_common::ProfileSummary;

pub(crate) fn needs_capture(profile: &ProfileSummary) -> bool {
    profile
        .ir
        .as_ref()
        .is_some_and(|ir| ir.missing_scans > 0 || ir.unknown_scans > 0 || ir.incompatible_scans > 0)
}

pub(crate) fn lines(profile: &ProfileSummary) -> Vec<String> {
    let Some(ir) = &profile.ir else {
        return vec!["IR compatibility: not reported by this daemon.".into()];
    };
    let mut lines = vec![format!(
        "IR for loaded recognizer: {} compatible scans.",
        ir.compatible_scans
    )];
    if needs_capture(profile) {
        lines.push(format!(
            "IR: {} missing, {} unknown, {} incompatible scans.",
            ir.missing_scans, ir.unknown_scans, ir.incompatible_scans
        ));
        lines.push("Fresh IR scans can add coverage; existing scans are kept.".into());
    }
    if ir.calibration_withheld {
        lines.push("IR calibration is paused while unknown IR scans remain.".into());
        lines.push("Compatible IR scans can match without calibration.".into());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_ir_guidance_distinguishes_unknown_zero_and_withheld() {
        let mut p: ProfileSummary = serde_json::from_str(r#"{"name":"P","scans":["s"]}"#).unwrap();
        assert_eq!(
            lines(&p),
            ["IR compatibility: not reported by this daemon."]
        );
        assert!(!needs_capture(&p));
        p.ir = Some(Default::default());
        assert_eq!(lines(&p), ["IR for loaded recognizer: 0 compatible scans."]);
        assert!(!needs_capture(&p));
        p.ir = Some(irlume_common::ProfileIrSummary {
            compatible_scans: 2,
            missing_scans: 1,
            unknown_scans: 1,
            incompatible_scans: 1,
            calibration_withheld: true,
        });
        assert!(needs_capture(&p));
        let guidance = lines(&p);
        assert_eq!(guidance.len(), 5);
        assert!(guidance
            .iter()
            .any(|s| s.contains("while unknown IR scans remain")));
        assert!(
            guidance.iter().all(|s| s.len() <= 66),
            "fit standard-width Faces rows"
        );
    }
}
