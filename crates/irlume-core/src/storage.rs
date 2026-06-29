//! Per-user face enrollment: up to 3 named face profiles, each holding multiple
//! named scans (Windows-Hello-style "improve recognition"). Stored as JSON under
//! the state dir (`IRLUME_STATE_DIR`, else `$HOME/.local/share/irlume` for dev,
//! else `/var/lib/irlume`), mode 0600. We store L2-normalized embeddings, never
//! raw images. The old single-profile format is migrated transparently on load.

use crate::{crypto, template_key};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

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

/// The physical camera(s) an enrollment was captured on, for anti-swap binding:
/// at auth, the live camera identity must still match (a swapped/virtual camera
/// is refused). Identities are `irlume_camera::device_identity` strings.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CameraBinding {
    #[serde(default)]
    pub rgb: Option<String>,
    #[serde(default)]
    pub ir: Option<String>,
}

/// All face data for one OS user.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Enrollment {
    pub user: String,
    pub profiles: Vec<FaceProfile>,
    /// Per-user opt-in: require both eyes open to unlock (default off).
    #[serde(default)]
    pub require_eyes_open: bool,
    /// Camera identity captured at enroll, verified at auth (anti-swap). `None`
    /// for pre-binding enrollments — enforcement only kicks in once bound.
    #[serde(default)]
    pub camera_binding: Option<CameraBinding>,
}

impl Enrollment {
    pub fn new(user: &str) -> Self {
        Self { user: user.into(), profiles: Vec::new(), require_eyes_open: false, camera_binding: None }
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

    /// Per-user IR-liveness floor `(depth_ratio, brightness)` derived from the
    /// enrolled scans' own IR calibration — the live frame must clear it, so the
    /// anti-screen / anti-photo threshold adapts to this user's camera/rig
    /// instead of a one-size global constant. Returns `None` until there are at
    /// least two IR-bearing scans (enough to be representative). The floor is the
    /// weakest enrolled value with a 25% margin below it (live IR varies).
    pub fn ir_calibration(&self) -> Option<(f32, f32)> {
        let mut depths = Vec::new();
        let mut brights = Vec::new();
        for p in &self.profiles {
            for s in &p.scans {
                if s.ir.is_some() && s.ir_depth > 0.0 && s.ir_brightness > 0.0 {
                    depths.push(s.ir_depth);
                    brights.push(s.ir_brightness);
                }
            }
        }
        if depths.len() < 2 {
            return None;
        }
        let min = |v: &[f32]| v.iter().copied().fold(f32::INFINITY, f32::min);
        Some((min(&depths) * 0.75, min(&brights) * 0.75))
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
        camera_binding: None,
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

/// On-disk wrapper for an encrypted enrollment (version 2). The plaintext under
/// `enc` is the same JSON an unencrypted `Enrollment` serializes to.
#[derive(Serialize, Deserialize)]
struct EncEnvelope {
    version: u32,
    /// base64 of `crypto`'s `nonce ‖ ciphertext+tag`.
    enc: String,
}

/// Serialize an enrollment, encrypting under `key` when one is supplied (TPM
/// host) or emitting pretty plaintext when not (dev / no-TPM). Pure — tested
/// without a TPM.
fn serialize_enrollment(e: &Enrollment, key: Option<&[u8]>) -> irlume_common::Result<Vec<u8>> {
    match key {
        Some(k) => {
            let json = serde_json::to_vec(e).map_err(|er| irlume_common::Error::Protocol(er.to_string()))?;
            let blob = crypto::encrypt(k, &json)?;
            let env = EncEnvelope { version: 2, enc: STANDARD.encode(blob) };
            serde_json::to_vec_pretty(&env).map_err(|er| irlume_common::Error::Protocol(er.to_string()))
        }
        None => serde_json::to_vec_pretty(e).map_err(|er| irlume_common::Error::Protocol(er.to_string())),
    }
}

/// Parse on-disk bytes into an `Enrollment`, handling all three formats:
/// encrypted (v2, needs `key`), plaintext multi-profile, and the legacy
/// single-profile layout (migrated). Pure — tested without a TPM.
fn deserialize_enrollment(data: &[u8], key: Option<&[u8]>) -> irlume_common::Result<Enrollment> {
    let v: serde_json::Value =
        serde_json::from_slice(data).map_err(|e| irlume_common::Error::Protocol(e.to_string()))?;
    if v.get("enc").is_some() {
        let env: EncEnvelope =
            serde_json::from_value(v).map_err(|e| irlume_common::Error::Protocol(e.to_string()))?;
        let key = key.ok_or_else(|| {
            irlume_common::Error::Policy("enrollment is encrypted but no template key is available".into())
        })?;
        let blob = STANDARD
            .decode(env.enc.as_bytes())
            .map_err(|e| irlume_common::Error::Protocol(format!("bad enc blob: {e}")))?;
        let plain = crypto::decrypt(key, &blob)?;
        serde_json::from_slice(&plain).map_err(|e| irlume_common::Error::Protocol(e.to_string()))
    } else if v.get("profiles").is_some() {
        serde_json::from_value(v).map_err(|e| irlume_common::Error::Protocol(e.to_string()))
    } else {
        let old: LegacyProfile =
            serde_json::from_value(v).map_err(|e| irlume_common::Error::Protocol(e.to_string()))?;
        Ok(migrate(old))
    }
}

/// Resolve the key to encrypt `user`'s templates with: the TPM-sealed template
/// key on a TPM host (generated on first save), or `None` on a no-TPM host
/// (plaintext fallback so dev boxes still work).
fn save_key(user: &str) -> irlume_common::Result<Option<Zeroizing<Vec<u8>>>> {
    if template_key::tpm_available() {
        Ok(Some(template_key::ensure_key(user)?))
    } else {
        Ok(None)
    }
}

pub fn save(e: &Enrollment) -> irlume_common::Result<()> {
    let dir = state_dir();
    fs::create_dir_all(&dir).map_err(|er| irlume_common::Error::Io(er.to_string()))?;
    let path = profile_path(&e.user);
    let key = save_key(&e.user)?;
    let bytes = serialize_enrollment(e, key.as_ref().map(|k| k.as_slice()))?;
    fs::write(&path, bytes).map_err(|er| irlume_common::Error::Io(er.to_string()))?;
    set_0600(&path);
    Ok(())
}

/// Load an enrollment, transparently decrypting (v2) and migrating the legacy
/// single-profile format. A plaintext file loads without touching the TPM; an
/// encrypted file unseals the template key (and fails cleanly — face auth then
/// falls back to the password — if the seal can no longer be satisfied).
pub fn load(user: &str) -> irlume_common::Result<Option<Enrollment>> {
    let path = profile_path(user);
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read(&path).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
    // Only unseal the key when the file is actually encrypted.
    let is_enc = serde_json::from_slice::<serde_json::Value>(&data)
        .map(|v| v.get("enc").is_some())
        .unwrap_or(false);
    let key = if is_enc { Some(template_key::load_key(user)?) } else { None };
    deserialize_enrollment(&data, key.as_ref().map(|k| k.as_slice())).map(Some)
}

pub fn delete(user: &str) -> irlume_common::Result<bool> {
    let path = profile_path(user);
    let existed = path.exists();
    if existed {
        fs::remove_file(&path).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
    }
    // Deleting all face data also retires the now-orphaned template key and its
    // recovery envelope (a fresh enrollment mints a new key).
    let _ = template_key::forget_key(user);
    let _ = template_key::forget_recovery(user);
    Ok(existed)
}

/// Every OS user with an enrollment on this host (the `<user>.json` stems in the
/// state dir), sorted. For 1:N identify and status reporting. Returns an empty
/// list if the state dir doesn't exist yet.
pub fn list_users() -> Vec<String> {
    let mut users = Vec::new();
    if let Ok(rd) = fs::read_dir(state_dir()) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                    users.push(stem.to_string());
                }
            }
        }
    }
    users.sort();
    users
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

    fn sample() -> Enrollment {
        Enrollment {
            user: "u".into(),
            profiles: vec![FaceProfile {
                name: "Face Profile 1".into(),
                scans: vec![FaceScan {
                    name: "Face Scan 1".into(),
                    rgb: vec![0.1, 0.2, 0.3, 0.4],
                    ir: Some(vec![0.5, 0.6]),
                    ir_depth: 1.4,
                    ir_brightness: 90.0,
                }],
            }],
            require_eyes_open: true,
            camera_binding: None,
        }
    }

    #[test]
    fn encrypted_round_trip_with_key() {
        let key = crypto::generate_key();
        let e = sample();
        let bytes = serialize_enrollment(&e, Some(&key)).unwrap();
        // The ciphertext must not leak the embeddings or the user in cleartext.
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("\"enc\""));
        assert!(!text.contains("Face Profile 1"));
        let back = deserialize_enrollment(&bytes, Some(&key)).unwrap();
        assert_eq!(back.user, "u");
        assert_eq!(back.total_scans(), 1);
        assert!(back.require_eyes_open);
        assert_eq!(back.profiles[0].scans[0].rgb, vec![0.1, 0.2, 0.3, 0.4]);
    }

    #[test]
    fn plaintext_round_trip_without_key() {
        let e = sample();
        let bytes = serialize_enrollment(&e, None).unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("Face Profile 1"));
        let back = deserialize_enrollment(&bytes, None).unwrap();
        assert_eq!(back.total_scans(), 1);
    }

    #[test]
    fn encrypted_file_needs_a_key_to_load() {
        let key = crypto::generate_key();
        let bytes = serialize_enrollment(&sample(), Some(&key)).unwrap();
        assert!(deserialize_enrollment(&bytes, None).is_err());
        assert!(deserialize_enrollment(&bytes, Some(&crypto::generate_key())).is_err());
    }

    fn scan_with_ir(depth: f32, bright: f32) -> FaceScan {
        FaceScan { name: "s".into(), rgb: vec![0.1; 4], ir: Some(vec![0.2; 4]), ir_depth: depth, ir_brightness: bright }
    }

    #[test]
    fn ir_calibration_needs_two_scans_then_floors_below_weakest() {
        // One IR scan -> not enough to characterise the user's rig.
        let mut e = Enrollment::new("u");
        e.profiles.push(FaceProfile { name: "p".into(), scans: vec![scan_with_ir(1.5, 100.0)] });
        assert!(e.ir_calibration().is_none());

        // Two+ scans -> floor at 75% of the weakest enrolled value.
        e.profiles[0].scans.push(scan_with_ir(1.2, 80.0));
        let (depth_floor, bright_floor) = e.ir_calibration().unwrap();
        assert!((depth_floor - 1.2 * 0.75).abs() < 1e-5);
        assert!((bright_floor - 80.0 * 0.75).abs() < 1e-5);
    }

    #[test]
    fn ir_calibration_ignores_scans_without_ir() {
        // RGB-only scans (no IR) must not count toward the floor.
        let mut e = Enrollment::new("u");
        e.profiles.push(FaceProfile {
            name: "p".into(),
            scans: vec![
                FaceScan { name: "a".into(), rgb: vec![0.1; 4], ir: None, ir_depth: 0.0, ir_brightness: 0.0 },
                scan_with_ir(1.5, 100.0),
            ],
        });
        assert!(e.ir_calibration().is_none()); // only one IR-bearing scan
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
