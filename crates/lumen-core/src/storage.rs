//! Per-user enrolled profiles. Embeddings are zeroized on drop; no raw images.

use lumen_vision::Embedding;
use zeroize::Zeroize;

/// One enrolled profile (a user may have several, e.g. "glasses", "dark").
pub struct Profile {
    pub name: String,
    pub templates: Vec<Embedding>,
    /// IR liveness calibration envelope captured at enrollment (per-user cues).
    // TODO: pub ir_calibration: IrCalibration,
    _priv: (),
}

impl Drop for Profile {
    fn drop(&mut self) {
        for t in &mut self.templates {
            t.zeroize();
        }
    }
}

impl Profile {
    pub fn new(name: String, templates: Vec<Embedding>) -> Self {
        Self { name, templates, _priv: () }
    }
}

/// Load/save profiles under [`lumen_common::STATE_DIR`] (root-owned, 0600).
pub struct Store { /* TODO: path, serde of profiles */ }

impl Store {
    pub fn open() -> lumen_common::Result<Self> {
        todo!()
    }
    pub fn profiles_for(&self, _user: &str) -> lumen_common::Result<Vec<Profile>> {
        todo!()
    }
}
