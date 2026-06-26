//! Per-user enrolled profiles (templates + IR calibration).
//!
//! Stored as JSON under the state dir (`IRLUME_STATE_DIR`, else
//! `$HOME/.local/share/irlume` for dev, else `/var/lib/irlume`). Files are
//! created mode 0600. We store L2-normalized embeddings, never raw images. A
//! production daemon would additionally TPM-seal the release secret (see `tpm`).

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// One enrolled user. `templates` are 512-D L2-normalized embeddings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub user: String,
    pub templates: Vec<Vec<f32>>,
    /// Per-user IR liveness calibration: enrolled center/edge depth ratios and
    /// face-region brightness, for tightening the gate to this user (P2 follow-up).
    #[serde(default)]
    pub ir_depth_samples: Vec<f32>,
    #[serde(default)]
    pub ir_brightness_samples: Vec<f32>,
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

pub fn save(p: &Profile) -> irlume_common::Result<()> {
    let dir = state_dir();
    fs::create_dir_all(&dir).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
    let path = profile_path(&p.user);
    let json = serde_json::to_vec_pretty(p).map_err(|e| irlume_common::Error::Protocol(e.to_string()))?;
    fs::write(&path, json).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
    set_0600(&path);
    Ok(())
}

pub fn load(user: &str) -> irlume_common::Result<Option<Profile>> {
    let path = profile_path(user);
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read(&path).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
    let p = serde_json::from_slice(&data).map_err(|e| irlume_common::Error::Protocol(e.to_string()))?;
    Ok(Some(p))
}

#[cfg(unix)]
fn set_0600(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn set_0600(_path: &std::path::Path) {}
