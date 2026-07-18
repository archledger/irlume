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

/// Max face profiles per account, one per person (e.g. self / a partner / a
/// trusted person). A face can only own one profile, so appearance variants
/// (glasses, lighting) are extra scans on that person's profile, not new
/// profiles. A 4th person requires deleting one.
pub const MAX_PROFILES: usize = 3;
/// Max scans per profile: one fresh enrollment plus four improve-recognition
/// rounds ([`DEFAULT_ENROLL_SCANS`] + 4 x [`IMPROVE_SCANS`]). Raised from 5:
/// scans now also feed the per-profile IR calibration fit (ADR-0004). The cap
/// is set where the 2026-07-15 enrollment-size sweep plateaued: calibrated
/// FRR at the production threshold improves steeply from 5 scans (25%) to 15
/// (17%) and flattens by 30 (16%), while past ~30 the fit's growing rank
/// starts to nudge impostor scores upward (FAR@0.40 0.14%→0.42% by 50) for
/// zero FRR gain. Best-of-N FAR inflation stays bounded by
/// [`crate::scaled_threshold`] (+0.074 at 30, under the +0.10 cap).
pub const MAX_SCANS_PER_PROFILE: usize = 30;
/// Scans captured by a fresh enrollment to bootstrap solid recognition and a
/// usable first calibration fit.
pub const DEFAULT_ENROLL_SCANS: usize = 10;
/// Scans added per improve-recognition round.
pub const IMPROVE_SCANS: usize = 5;

/// One quality-gated capture under a profile. `rgb` is a 512-D L2-normalized
/// AuraFace embedding; `ir` is the IR-face embedding for dark operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaceScan {
    pub name: String,
    pub rgb: Vec<f32>,
    #[serde(default)]
    pub ir: Option<Vec<f32>>,
    /// Embedding space `ir` lives in: `"raw"` (no adapter) or
    /// `"adapter:<sha256 prefix>"` of the adapter that produced it. Templates
    /// only match probes from the same space, so swapping or removing the
    /// adapter can never silently score against stale-space templates.
    /// `None` = scan predates space tagging; grandfathered as compatible.
    #[serde(default)]
    pub ir_space: Option<String>,
    /// Per-scan IR liveness calibration (center/edge depth, face brightness).
    #[serde(default)]
    pub ir_depth: f32,
    #[serde(default)]
    pub ir_brightness: f32,
    /// Head `pitch_frac` at capture. The median across scans is this user's
    /// frontal neutral, used to CENTRE the enrollment framing band on their
    /// camera (a below-eye laptop cam reads pitch high even when level). 0.0 =
    /// not recorded (pre-calibration scan); ignored by [`Enrollment::pitch_neutral`].
    #[serde(default)]
    pub pitch: f32,
}

/// A face profile: a named set of scans of one face.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaceProfile {
    pub name: String,
    pub scans: Vec<FaceScan>,
    /// Per-profile IR calibration (ADR-0004), fitted from this profile's own
    /// scan pairs at enroll/add-scan time. Only fitted and applied when no
    /// global IR adapter is loaded (raw embedding space); `None` otherwise
    /// and on profiles from before the feature.
    #[serde(default)]
    pub ir_calib: Option<crate::calib::IrCalibration>,
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
    /// Per-user opt-in: require a blink challenge (temporal liveness) to unlock
    /// (default off). Defeats static IR-reflective prints: a print can't blink.
    /// See ADR-0002. Only enforced when IR is available (the glint challenge needs
    /// the emitter).
    #[serde(default)]
    pub require_challenge: bool,
    /// Camera identity captured at enroll, verified at auth (anti-swap). `None`
    /// for pre-binding enrollments; enforcement only kicks in once bound.
    #[serde(default)]
    pub camera_binding: Option<CameraBinding>,
}

impl Enrollment {
    pub fn new(user: &str) -> Self {
        Self {
            user: user.into(),
            profiles: Vec::new(),
            require_eyes_open: false,
            require_challenge: false,
            camera_binding: None,
        }
    }

    /// Total scans across all profiles (drives threshold scaling).
    pub fn total_scans(&self) -> usize {
        self.profiles.iter().map(|p| p.scans.len()).sum()
    }

    /// Every RGB template with its (profile, scan) labels, for 1:N matching.
    pub fn rgb_scans(&self) -> Vec<(&str, &str, &[f32])> {
        self.profiles
            .iter()
            .flat_map(|p| {
                p.scans
                    .iter()
                    .map(move |s| (p.name.as_str(), s.name.as_str(), s.rgb.as_slice()))
            })
            .collect()
    }

    /// Every IR template (dark path), with (profile, scan) labels.
    pub fn ir_scans(&self) -> Vec<(&str, &str, &[f32])> {
        self.profiles
            .iter()
            .flat_map(|p| {
                p.scans.iter().filter_map(move |s| {
                    s.ir.as_ref()
                        .map(|ir| (p.name.as_str(), s.name.as_str(), ir.as_slice()))
                })
            })
            .collect()
    }

    /// IR templates compatible with the live pipeline: same embedding space
    /// (untagged legacy scans are grandfathered) and same dimensionality as
    /// the probe. A v1 256-D or foreign-adapter template never reaches the
    /// cosine matcher, where it would score garbage instead of failing loud.
    pub fn ir_scans_for(&self, space: &str, dim: usize) -> Vec<(&str, &str, &[f32])> {
        self.profiles
            .iter()
            .flat_map(|p| {
                p.scans.iter().filter_map(move |s| {
                    let ir = s.ir.as_ref()?;
                    if ir.len() != dim {
                        return None;
                    }
                    match &s.ir_space {
                        Some(sp) if sp != space => None,
                        _ => Some((p.name.as_str(), s.name.as_str(), ir.as_slice())),
                    }
                })
            })
            .collect()
    }

    /// IR scans that were enrolled in a DIFFERENT embedding space than the live
    /// pipeline (e.g. under an IR adapter that is no longer loaded). These are
    /// skipped by [`Enrollment::ir_scans_for`], so dark/dim login cannot match
    /// them: the user must re-enroll. Untagged legacy scans are grandfathered
    /// (they are retagged to the live space by [`Enrollment::retag_untagged_ir`]),
    /// so this counts only genuinely foreign-tagged scans. Call AFTER retagging.
    pub fn stale_ir_scans(&self, live_space: &str) -> usize {
        self.profiles
            .iter()
            .flat_map(|p| &p.scans)
            .filter(|s| s.ir.is_some())
            .filter(|s| matches!(&s.ir_space, Some(sp) if sp != live_space))
            .count()
    }

    /// IR scans matching that dark/dim login CAN score: tagged with the live
    /// space, or untagged (grandfathered, see [`Enrollment::retag_untagged_ir`]).
    /// The complement of [`Enrollment::stale_ir_scans`]. Used to decide whether
    /// stale scans are an outage (none usable: dark login is broken, tell the
    /// user to re-enroll) or leftovers (fresh scans exist alongside them, dark
    /// login works, stay quiet).
    pub fn usable_ir_scans(&self, live_space: &str) -> usize {
        self.profiles
            .iter()
            .flat_map(|p| &p.scans)
            .filter(|s| s.ir.is_some())
            .filter(|s| s.ir_space.as_deref().is_none_or(|sp| sp == live_space))
            .count()
    }

    /// Stamp untagged IR scans with the space of the pipeline they were
    /// captured under (only scans matching the live pipeline's embedding
    /// dimension). Called by the daemon at startup while the pipeline is
    /// unchanged, so that a FUTURE adapter swap/removal finds every scan
    /// explicitly tagged and can fail loud ("re-enroll") instead of scoring
    /// across spaces. Idempotent; returns how many scans were stamped.
    pub fn retag_untagged_ir(&mut self, space: &str, dim: usize) -> usize {
        let mut n = 0;
        for p in &mut self.profiles {
            for s in &mut p.scans {
                if let Some(ir) = &s.ir {
                    if s.ir_space.is_none() && ir.len() == dim {
                        s.ir_space = Some(space.into());
                        n += 1;
                    }
                }
            }
        }
        n
    }

    /// Per-user IR-liveness floor `(depth_ratio, brightness)` derived from the
    /// enrolled scans' own IR calibration: the live frame must clear it, so the
    /// anti-screen / anti-photo threshold adapts to this user's camera/rig
    /// instead of a one-size global constant. Returns `None` until there are at
    /// least two IR-bearing scans (enough to be representative). The floor is the
    /// weakest enrolled value with a 25% margin below it (live IR varies).
    /// Per-user IR **depth** floor (center/edge ratio, a 3D-structure cue) for the
    /// anti-screen/photo gate: 75% of the weakest enrolled IR depth. Needs ≥2 IR
    /// scans. DEPTH ONLY; the former per-user IR *brightness* floor was removed:
    /// IR face brightness is strongly ambient-dependent (emitter-only ~40 in the
    /// dark vs ~140 in a lit room, measured on the ASUS Hello cam), so a brightness
    /// floor derived from lit enrollment false-rejects a genuine dim/night login as
    /// a "screen/photo". The global liveness gate (`evaluate`) already enforces an
    /// ambient-tolerant IR brightness floor (`IR_FACE_MIN_BRIGHTNESS`) and depth floor
    /// (`DEPTH_MIN_RATIO`); this adds a personalized depth tightening on top.
    pub fn ir_calibration(&self) -> Option<f32> {
        let mut depths = Vec::new();
        for p in &self.profiles {
            for s in &p.scans {
                if s.ir.is_some() && s.ir_depth > 0.0 {
                    depths.push(s.ir_depth);
                }
            }
        }
        if depths.len() < 2 {
            return None;
        }
        let min = depths.iter().copied().fold(f32::INFINITY, f32::min);
        Some(min * 0.75)
    }

    /// This user's frontal pitch neutral (the median of the per-scan capture
    /// pitches), or `None` until at least two calibrated scans exist. Lets the
    /// framing guide + capture gate centre on where a LEVEL face actually reads
    /// on this camera instead of a hand-tuned global constant. Scans with pitch
    /// 0.0 (pre-calibration) are ignored, so it stays backward-compatible.
    pub fn pitch_neutral(&self) -> Option<f32> {
        let mut v: Vec<f32> = self
            .profiles
            .iter()
            .flat_map(|p| p.scans.iter())
            .map(|s| s.pitch)
            .filter(|&p| p > 0.0)
            .collect();
        if v.len() < 2 {
            return None;
        }
        v.sort_by(f32::total_cmp);
        Some(v[v.len() / 2])
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
            ir_space: None, // legacy scans predate space tagging

            ir_depth: old.ir_depth_samples.get(i).copied().unwrap_or(0.0),
            ir_brightness: old.ir_brightness_samples.get(i).copied().unwrap_or(0.0),
            pitch: 0.0, // legacy scans predate pitch calibration
        })
        .collect();
    Enrollment {
        user: old.user,
        profiles: vec![FaceProfile {
            ir_calib: None,
            name: "Face Profile 1".into(),
            scans,
        }],
        require_eyes_open: false,
        require_challenge: false,
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
/// host) or emitting pretty plaintext when not (dev / no-TPM). Pure; tested
/// without a TPM.
fn serialize_enrollment(e: &Enrollment, key: Option<&[u8]>) -> irlume_common::Result<Vec<u8>> {
    match key {
        Some(k) => {
            // The serialized enrollment is template plaintext; keep it zeroized
            // once the encrypted blob exists (mirrors the load path).
            let json = Zeroizing::new(
                serde_json::to_vec(e)
                    .map_err(|er| irlume_common::Error::Protocol(er.to_string()))?,
            );
            let blob = crypto::encrypt(k, &json)?;
            let env = EncEnvelope {
                version: 2,
                enc: STANDARD.encode(blob),
            };
            serde_json::to_vec_pretty(&env)
                .map_err(|er| irlume_common::Error::Protocol(er.to_string()))
        }
        None => serde_json::to_vec_pretty(e)
            .map_err(|er| irlume_common::Error::Protocol(er.to_string())),
    }
}

/// Parse on-disk bytes into an `Enrollment`, handling all three formats:
/// encrypted (v2, needs `key`), plaintext multi-profile, and the legacy
/// single-profile layout (migrated). Pure; tested without a TPM.
fn deserialize_enrollment(data: &[u8], key: Option<&[u8]>) -> irlume_common::Result<Enrollment> {
    let v: serde_json::Value =
        serde_json::from_slice(data).map_err(|e| irlume_common::Error::Protocol(e.to_string()))?;
    if v.get("enc").is_some() {
        let env: EncEnvelope =
            serde_json::from_value(v).map_err(|e| irlume_common::Error::Protocol(e.to_string()))?;
        let key = key.ok_or_else(|| {
            irlume_common::Error::Policy(
                "enrollment is encrypted but no template key is available".into(),
            )
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
    // Atomic + never world-readable: 0600 temp file in the same dir, then
    // rename over the target: a crash mid-write can't leave a truncated
    // profile, and there is no umask window on the real path.
    let tmp = path.with_extension("json.tmp");
    write_0600(&tmp, &bytes).map_err(|er| irlume_common::Error::Io(er.to_string()))?;
    fs::rename(&tmp, &path).map_err(|er| irlume_common::Error::Io(er.to_string()))?;
    Ok(())
}

/// Create/truncate `path` with mode 0600 and write `bytes` (unix).
#[cfg(unix)]
fn write_0600(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(not(unix))]
fn write_0600(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)
}

/// Load an enrollment, transparently decrypting (v2) and migrating the legacy
/// single-profile format. A plaintext file loads without touching the TPM; an
/// encrypted file unseals the template key (and fails cleanly, with face auth
/// falling back to the password, if the seal can no longer be satisfied).
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
    let key = if is_enc {
        Some(template_key::load_key(user)?)
    } else {
        None
    };
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
                ir_calib: None,
                name: "Face Profile 1".into(),
                scans: vec![FaceScan {
                    name: "Face Scan 1".into(),
                    rgb: vec![0.1, 0.2, 0.3, 0.4],
                    ir: Some(vec![0.5, 0.6]),
                    ir_space: None,
                    ir_depth: 1.4,
                    ir_brightness: 90.0,
                    pitch: 0.52,
                }],
            }],
            require_eyes_open: true,
            require_challenge: false,
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
        FaceScan {
            name: "s".into(),
            rgb: vec![0.1; 4],
            ir: Some(vec![0.2; 4]),
            ir_space: None,
            ir_depth: depth,
            ir_brightness: bright,
            pitch: 0.0,
        }
    }

    fn scan_with_pitch(pitch: f32) -> FaceScan {
        FaceScan {
            name: "s".into(),
            rgb: vec![0.1; 4],
            ir: None,
            ir_space: None,
            ir_depth: 0.0,
            ir_brightness: 0.0,
            pitch,
        }
    }

    #[test]
    fn pitch_neutral_is_median_of_calibrated_scans() {
        let mut e = Enrollment::new("u");
        // One calibrated scan -> not enough.
        e.profiles.push(FaceProfile {
            ir_calib: None,
            name: "p".into(),
            scans: vec![scan_with_pitch(0.60)],
        });
        assert!(e.pitch_neutral().is_none());
        // Add more -> median of {0.60, 0.58, 0.62} = 0.60.
        e.profiles[0].scans.push(scan_with_pitch(0.58));
        e.profiles[0].scans.push(scan_with_pitch(0.62));
        assert!((e.pitch_neutral().unwrap() - 0.60).abs() < 1e-6);
        // Pre-calibration scans (pitch 0.0) are ignored.
        e.profiles[0].scans.push(scan_with_pitch(0.0));
        assert!((e.pitch_neutral().unwrap() - 0.60).abs() < 1e-6);
    }

    #[test]
    fn ir_calibration_needs_two_scans_then_floors_below_weakest() {
        // One IR scan -> not enough to characterise the user's rig.
        let mut e = Enrollment::new("u");
        e.profiles.push(FaceProfile {
            ir_calib: None,
            name: "p".into(),
            scans: vec![scan_with_ir(1.5, 100.0)],
        });
        assert!(e.ir_calibration().is_none());

        // Two+ scans -> depth floor at 75% of the weakest enrolled depth.
        // (brightness is intentionally NOT floored per-user; it is ambient-dependent.)
        e.profiles[0].scans.push(scan_with_ir(1.2, 80.0));
        let depth_floor = e.ir_calibration().unwrap();
        assert!((depth_floor - 1.2 * 0.75).abs() < 1e-5);
    }

    fn scan_in_space(name: &str, dim: usize, space: Option<&str>) -> FaceScan {
        FaceScan {
            name: name.into(),
            rgb: vec![0.1; 4],
            ir: Some(vec![0.2; dim]),
            ir_space: space.map(Into::into),
            ir_depth: 0.0,
            ir_brightness: 0.0,
            pitch: 0.0,
        }
    }

    #[test]
    fn ir_scans_for_filters_space_and_dimension() {
        let mut e = Enrollment::new("u");
        e.profiles.push(FaceProfile {
            ir_calib: None,
            name: "p".into(),
            scans: vec![
                scan_in_space("legacy-untagged", 4, None),
                scan_in_space("raw", 4, Some("raw")),
                scan_in_space("v3", 4, Some("adapter:abc123")),
                scan_in_space("v1-256", 2, None), // stale dim: never matches a 4-D probe
            ],
        });
        // Raw pipeline: legacy grandfathered + raw-tagged; v3-tagged excluded.
        let raw: Vec<_> = e.ir_scans_for("raw", 4).iter().map(|s| s.1).collect();
        assert_eq!(raw, vec!["legacy-untagged", "raw"]);
        // Adapter pipeline: legacy grandfathered + matching adapter; raw excluded.
        let v3: Vec<_> = e
            .ir_scans_for("adapter:abc123", 4)
            .iter()
            .map(|s| s.1)
            .collect();
        assert_eq!(v3, vec!["legacy-untagged", "v3"]);
        // A different adapter build sees only the grandfathered scan.
        assert_eq!(e.ir_scans_for("adapter:zzz999", 4).len(), 1);
        // The unfiltered accessor still reports every IR-bearing scan.
        assert_eq!(e.ir_scans().len(), 4);
    }

    #[test]
    fn retag_untagged_ir_stamps_only_matching_legacy_scans() {
        let mut e = Enrollment::new("u");
        e.profiles.push(FaceProfile {
            ir_calib: None,
            name: "p".into(),
            scans: vec![
                scan_in_space("legacy", 4, None),          // stamped
                scan_in_space("tagged", 4, Some("other")), // left alone
                scan_in_space("stale-dim", 2, None),       // wrong dim: left alone
            ],
        });
        assert_eq!(e.retag_untagged_ir("adapter:abc123", 4), 1);
        assert_eq!(
            e.profiles[0].scans[0].ir_space.as_deref(),
            Some("adapter:abc123")
        );
        assert_eq!(e.profiles[0].scans[1].ir_space.as_deref(), Some("other"));
        assert!(e.profiles[0].scans[2].ir_space.is_none());
        // Idempotent: nothing left to stamp.
        assert_eq!(e.retag_untagged_ir("adapter:abc123", 4), 0);
    }

    #[test]
    fn scan_json_without_ir_space_loads_as_untagged() {
        // Enrollments written before space tagging must load unchanged.
        let json = r#"{"name":"s","rgb":[0.1],"ir":[0.2]}"#;
        let s: FaceScan = serde_json::from_str(json).unwrap();
        assert!(s.ir_space.is_none());
        assert_eq!(s.ir.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn ir_calibration_ignores_scans_without_ir() {
        // RGB-only scans (no IR) must not count toward the floor.
        let mut e = Enrollment::new("u");
        e.profiles.push(FaceProfile {
            ir_calib: None,
            name: "p".into(),
            scans: vec![
                FaceScan {
                    name: "a".into(),
                    rgb: vec![0.1; 4],
                    ir: None,
                    ir_space: None,
                    ir_depth: 0.0,
                    ir_brightness: 0.0,
                    pitch: 0.0,
                },
                scan_with_ir(1.5, 100.0),
            ],
        });
        assert!(e.ir_calibration().is_none()); // only one IR-bearing scan
    }

    #[test]
    fn default_names_fill_first_free_slot() {
        let mut e = Enrollment::new("u");
        assert_eq!(e.next_profile_name(), "Face Profile 1");
        e.profiles.push(FaceProfile {
            ir_calib: None,
            name: "Face Profile 1".into(),
            scans: vec![],
        });
        assert_eq!(e.next_profile_name(), "Face Profile 2");
        let p = &e.profiles[0];
        assert_eq!(p.next_scan_name(), "Face Scan 1");
    }

    #[test]
    fn stale_and_usable_ir_counts_partition_the_scans() {
        let ir_scan = |name: &str, space: Option<&str>| FaceScan {
            name: name.into(),
            rgb: vec![0.0; 4],
            ir: Some(vec![0.0; 4]),
            ir_space: space.map(String::from),
            ir_depth: 0.0,
            ir_brightness: 0.0,
            pitch: 0.0,
        };
        let mut e = Enrollment::new("u");
        e.profiles.push(FaceProfile {
            ir_calib: None,
            name: "P".into(),
            scans: vec![
                ir_scan("adapter-era", Some("adapter:deadbeef0123")),
                ir_scan("fresh", Some("raw")),
                ir_scan("legacy-untagged", None),
            ],
        });
        // The upgrade-outage notice keys off this split: stale>0 AND usable==0.
        assert_eq!(e.stale_ir_scans("raw"), 1);
        assert_eq!(e.usable_ir_scans("raw"), 2); // tagged-current + grandfathered
                                                 // Post-0.2.0, pre-re-enroll: everything stale, nothing usable -> notice.
        e.profiles[0].scans.retain(|s| s.name == "adapter-era");
        assert_eq!(e.stale_ir_scans("raw"), 1);
        assert_eq!(e.usable_ir_scans("raw"), 0);
        // An RGB-only scan (no ir) counts for neither side.
        e.profiles[0].scans.push(FaceScan {
            ir: None,
            ..ir_scan("rgb-only", None)
        });
        assert_eq!(e.usable_ir_scans("raw"), 0);
    }
}
