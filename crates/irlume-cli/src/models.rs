// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Surfaces over the SHIPPED model set (the models-v1 release artifacts).
//!
//! The third-party / bring-your-own model lane was removed (ADR-0015): irlume
//! ships and supports exactly the models it was validated with — YuNet
//! detection, BlazeFace rescue, the MediaPipe landmarker, AuraFace identity
//! (RGB + IR), the ViT RGB PAD cue, and the FLIR IR PAD cue. There is no
//! catalog, no enable/disable flow, and no external recognizer path; the
//! functions here resolve where the shipped files live for `doctor` and map
//! recognizer-space names for `profiles forget-model`.

use std::process::ExitCode;

/// The removed `irlume models` command's answer: one clear line, not silence.
pub fn removed_notice() -> ExitCode {
    eprintln!(
        "[models] third-party model support was removed; irlume ships its full model \
         set (models-v1). Check installed weights with: irlume doctor"
    );
    ExitCode::from(2)
}

/// A pipeline stage's shipped model file and where it resolved.
pub(crate) struct StageStatus {
    pub stage: &'static str,
    pub file: Option<&'static str>,
    pub resolved: Option<crate::commands::ModelCandidate>,
    pub required: bool,
}

/// The pipeline stages in order, with what each loads.
///
/// The blaze rescue detector and the IR adapter are deliberately absent: they
/// are auxiliaries of the detection and recognition stages, not stages of
/// their own.
pub(crate) fn stage_statuses() -> Vec<StageStatus> {
    [
        (
            "detection",
            "face_detection_yunet_2023mar.onnx",
            "IRLUME_DET_MODEL",
            true,
        ),
        (
            "landmarks",
            "face_landmark_detector.tflite",
            "IRLUME_MESH_MODEL",
            false,
        ),
        ("recognition", "glintr100.onnx", "IRLUME_MODEL", true),
    ]
    .into_iter()
    .map(|(stage, file, env, required)| StageStatus {
        stage,
        file: Some(file),
        resolved: crate::commands::resolve_model_candidate(file, env),
        required,
    })
    .collect()
}

/// Resolve a `profiles forget-model <name>` argument to the stored recognizer
/// space tag it names.
///
/// `shipped` names the legacy tag; any literal `embed:<64-hex>` names a
/// specific weights digest (lowercased: stored tags are lowercase and the
/// daemon compares case-sensitively). This stays after the third-party lane's
/// removal so an enrollment that still carries scans from an abandoned
/// external recognizer can be cleaned without deleting every profile.
pub(crate) fn recognizer_space_for(name: &str) -> Result<String, String> {
    if name == "shipped" {
        return Ok(irlume_core::storage::LEGACY_RECOGNIZER_SPACE.to_string());
    }
    if let Some(hex) = name.strip_prefix("embed:") {
        if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(format!("embed:{}", hex.to_ascii_lowercase()));
        }
        return Err(format!(
            "'{name}': an embed space is 'embed:' plus exactly 64 hex characters"
        ));
    }
    Err(format!(
        "'{name}': unknown model (with third-party support removed, forget-model \
         accepts 'shipped' or a literal 'embed:<64-hex>' space)"
    ))
}

#[cfg(test)]
mod tests {
    use super::recognizer_space_for;

    #[test]
    fn forget_model_accepts_shipped_and_literal_spaces_only() {
        assert_eq!(
            recognizer_space_for("shipped").unwrap(),
            irlume_core::storage::LEGACY_RECOGNIZER_SPACE
        );
        assert_eq!(
            recognizer_space_for(
                "embed:ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            )
            .unwrap(),
            "embed:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        );
        // Catalog names are gone with the lane; a catalog-shaped argument
        // must be refused, not silently interpreted.
        assert!(recognizer_space_for("buffalo").is_err());
        assert!(recognizer_space_for("embed:xyz").is_err());
    }
}
