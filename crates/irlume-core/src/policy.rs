//! System auth-method policy: which biometric modality is active. Set by
//! `irlume fingerprint enable/disable`; read by the daemon so it can stay silent
//! (let `pam_fprintd` drive) when the user has chosen fingerprint.
//!
//! One line in `/etc/irlume/method` (override: `IRLUME_METHOD_CONF`): the method
//! string. Absent/unreadable ⇒ `Auto` (face as usual).

use std::path::PathBuf;

/// The active authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Method {
    /// Default: face (RGB/IR) is the irlume modality.
    #[default]
    Auto,
    /// Face explicitly chosen (same behaviour as Auto for the daemon).
    Face,
    /// Fingerprint chosen: the daemon disables face so `pam_fprintd` drives.
    Fingerprint,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Auto => "auto",
            Method::Face => "face",
            Method::Fingerprint => "fingerprint",
        }
    }
    pub fn parse(s: &str) -> Method {
        match s.trim().to_lowercase().as_str() {
            "fingerprint" | "finger" | "fp" => Method::Fingerprint,
            "face" => Method::Face,
            _ => Method::Auto,
        }
    }
    /// True when face should be disabled (fingerprint mode).
    pub fn face_disabled(&self) -> bool {
        matches!(self, Method::Fingerprint)
    }
}

fn path() -> PathBuf {
    std::env::var("IRLUME_METHOD_CONF").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/etc/irlume/method"))
}

/// The active method (default `Auto` if unset/unreadable).
pub fn method() -> Method {
    std::fs::read_to_string(path()).map(|s| Method::parse(&s)).unwrap_or_default()
}

/// Persist the active method (creates `/etc/irlume` if needed; needs root).
pub fn set_method(m: Method) -> irlume_common::Result<()> {
    let p = path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| irlume_common::Error::Io(e.to_string()))?;
    }
    std::fs::write(&p, m.as_str()).map_err(|e| irlume_common::Error::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_roundtrip() {
        for m in [Method::Auto, Method::Face, Method::Fingerprint] {
            assert_eq!(Method::parse(m.as_str()), m);
        }
        assert_eq!(Method::parse("FP"), Method::Fingerprint);
        assert_eq!(Method::parse("nonsense"), Method::Auto);
        assert!(Method::Fingerprint.face_disabled());
        assert!(!Method::Auto.face_disabled());
    }
}
