//! Per-user face enrollment: up to 3 named face profiles, each holding multiple
//! named scans (Windows-Hello-style "improve recognition"). Stored as JSON under
//! the state dir (`IRLUME_STATE_DIR`, else `$HOME/.local/share/irlume` for dev,
//! else `/var/lib/irlume`), mode 0600. We store L2-normalized embeddings, never
//! raw images. The old single-profile format is migrated transparently on load.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Max face profiles per account (e.g. self / self-with-glasses / a trusted
/// person). A 4th requires deleting one.
pub const MAX_PROFILES: usize = 3;
/// Max scans per profile. Recognition gains plateau past a few; more inflates
/// the false-accept surface (mitigated by [`crate::scaled_threshold`]).
pub const MAX_SCANS_PER_PROFILE: usize = 5;
/// Scans captured by a fresh enrollment to bootstrap solid recognition.
pub const DEFAULT_ENROLL_SCANS: usize = 3;

/// One quality-gated capture under a profile. `rgb` is a 512-D L2-normalized
/// AuraFace embedding; `ir` is the IR-face embedding for dark operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaceScan {
    pub name: String,
    pub rgb: Vec<f32>,
    #[serde(default)]
    pub ir: Option<Vec<f32>>,
    /// Per-scan IR liveness calibration (center/edge depth, face brightness).
    #[serde(default)]
    pub ir_depth: f32,
    #[serde(default)]
    pub ir_brightness: f32,
}

/// A face profile: a named set of scans of one face.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaceProfile {
    pub name: String,
    pub scans: Vec<FaceScan>,
}

/// All face data for one OS user.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Enrollment {
    pub user: String,
    pub profiles: Vec<FaceProfile>,
    /// Per-user opt-in: require both eyes open to unlock (default off).
    #[serde(default)]
    pub require_eyes_open: bool,
}

impl Enrollment {
    pub fn new(user: &str) -> Self {
        Self { user: user.into(), profiles: Vec::new(), require_eyes_open: false }
    }

    /// Total scans across all profiles (drives threshold scaling).
    pub fn total_scans(&self) -> usize {
        self.profiles.iter().map(|p| p.scans.len()).sum()
    }

    /// Every RGB template with its (profile, scan) labels, for 1:N matching.
    pub fn rgb_scans(&self) -> Vec<(&str, &str, &[f32])> {
        self.profiles
            .iter()
            .flat_map(|p| p.scans.iter().map(move |s| (p.name.as_str(), s.name.as_str(), s.rgb.as_slice())))
            .collect()
    }

    /// Every IR template (dark path), with (profile, scan) labels.
    pub fn ir_scans(&self) -> Vec<(&str, &str, &[f32])> {
        self.profiles
            .iter()
            .flat_map(|p| {
                p.scans.iter().filter_map(move |s| s.ir.as_ref().map(|ir| (p.name.as_str(), s.name.as_str(), ir.as_slice())))
            })
            .collect()
    }

    /// Default name for the next profile ("Face Profile N", first free slot).
    pub fn next_profile_name(&self) -> String {
        for n in 1..=MAX_PROFILES {
            let cand = format!("Face Profile {n}");
            if !self.profiles.iter().any(|p| p.name == cand) {
                return cand;
            }
        }
        format!("Face Profile {}", self.profiles.len() + 1)
    }
}

impl FaceProfile {
    /// Default name for the next scan ("Face Scan N", first free slot).
    pub fn next_scan_name(&self) -> String {
        for n in 1..=(MAX_SCANS_PER_PROFILE + 1) {
            let cand = format!("Face Scan {n}");
            if !self.scans.iter().any(|s| s.name == cand) {
                return cand;
            }
        }
        format!("Face Scan {}", self.scans.len() + 1)
    }
}

// --- legacy (pre-multi-profile) format, for transparent migration ---
#[derive(Deserialize)]
struct LegacyProfile {
    user: String,
    #[serde(default)]
    templates: Vec<Vec<f32>>,
    #[serde(default)]
    ir_templates: Vec<Vec<f32>>,
    #[serde(default)]
    ir_depth_samples: Vec<f32>,
    #[serde(default)]
    ir_brightness_samples: Vec<f32>,
}

fn migrate(old: LegacyProfile) -> Enrollment {
    let scans = old
        .templates
        .iter()
        .enumerate()
        .map(|(i, t)| FaceScan {
            name: format!("Face Scan {}", i + 1),
            rgb: t.clone(),
            ir: old.ir_templates.get(i).cloned(),
            ir_depth: old.ir_depth_samples.get(i).copied().unwrap_or(0.0),
            ir_brightness: old.ir_brightness_samples.get(i).copied().unwrap_or(0.0),
        })
        .collect();
    Enrollment {
        user: old.user,
        profiles: vec![FaceProfile { name: "Face Profile 1".into(), scans }],
        require_eyes_open: false,
    }
}

fn state_dir() -> PathBuf {
    if let Ok(d) = std::env::var("IRLUME_STATE_DIR") {
        return PathBuf::from(d);
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".local/share/irlume");
    }
    PathBuf::from(irlume_common::STATE_DIR)
}

pub fn profile_path(user: &str) -> PathBuf {
    state_dir().join(format!("{user}.json"))
}

pub fn save(e: &Enrollment) -> irlume_common::Result<()> {
    let dir = state_dir();
    fs::create_dir_all(&dir).map_err(|er| irlume_common::Error::Io(er.to_string()))?;
    let path = profile_path(&e.user);
    let json = serde_json::to_vec_pretty(e).map_err(|er| irlume_common::Error::Protocol(er.to_string()))?;
    fs::write(&path, json).map_err(|er| irlume_common::Error::Io(er.to_string()))?;
    set_0600(&path);
    Ok(())
}

/// Load an enrollment, transparently migrating the legacy single-profile format.
pub fn load(user: &str) -> irlume_common::Result<Option<Enrollment>> {
    let path = profile_path(user);
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read(&path).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
    // New format has a "profiles" array; legacy has "templates".
    let v: serde_json::Value =
        serde_json::from_slice(&data).map_err(|e| irlume_common::Error::Protocol(e.to_string()))?;
    if v.get("profiles").is_some() {
        let e = serde_json::from_value(v).map_err(|e| irlume_common::Error::Protocol(e.to_string()))?;
        Ok(Some(e))
    } else {
        let old: LegacyProfile =
            serde_json::from_value(v).map_err(|e| irlume_common::Error::Protocol(e.to_string()))?;
        Ok(Some(migrate(old)))
    }
}

pub fn delete(user: &str) -> irlume_common::Result<bool> {
    let path = profile_path(user);
    if path.exists() {
        fs::remove_file(&path).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(unix)]
fn set_0600(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn set_0600(_path: &std::path::Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_format_migrates_to_one_profile() {
        let old = LegacyProfile {
            user: "u".into(),
            templates: vec![vec![0.1; 4], vec![0.2; 4]],
            ir_templates: vec![vec![0.3; 4]],
            ir_depth_samples: vec![1.4],
            ir_brightness_samples: vec![90.0],
        };
        let e = migrate(old);
        assert_eq!(e.profiles.len(), 1);
        assert_eq!(e.profiles[0].name, "Face Profile 1");
        assert_eq!(e.profiles[0].scans.len(), 2);
        assert_eq!(e.profiles[0].scans[0].name, "Face Scan 1");
        assert_eq!(e.profiles[0].scans[0].ir.as_ref().unwrap().len(), 4);
        assert!(e.profiles[0].scans[1].ir.is_none()); // only one ir template
        assert_eq!(e.total_scans(), 2);
        assert!(!e.require_eyes_open);
    }

    #[test]
    fn default_names_fill_first_free_slot() {
        let mut e = Enrollment::new("u");
        assert_eq!(e.next_profile_name(), "Face Profile 1");
        e.profiles.push(FaceProfile { name: "Face Profile 1".into(), scans: vec![] });
        assert_eq!(e.next_profile_name(), "Face Profile 2");
        let p = &e.profiles[0];
        assert_eq!(p.next_scan_name(), "Face Scan 1");
    }
}
