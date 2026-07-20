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
    std::env::var("IRLUME_METHOD_CONF")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/irlume/method"))
}

/// The active method (default `Auto` if unset/unreadable).
pub fn method() -> Method {
    std::fs::read_to_string(path())
        .map(|s| Method::parse(&s))
        .unwrap_or_default()
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

    #[test]
    fn parse_handles_aliases_and_whitespace_and_case() {
        // Every accepted fingerprint spelling, plus surrounding whitespace and
        // mixed case, must resolve to Fingerprint.
        for s in ["finger", "  Fingerprint\n", "FP", "\tfp "] {
            assert_eq!(Method::parse(s), Method::Fingerprint, "{s:?}");
        }
        assert_eq!(Method::parse("  FACE  "), Method::Face);
        // Only Fingerprint disables face; Face behaves like Auto for the daemon.
        assert!(!Method::Face.face_disabled());
    }

    #[test]
    fn path_honours_env_override() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        std::env::set_var("IRLUME_METHOD_CONF", "/tmp/irlume-method-override");
        assert_eq!(path(), PathBuf::from("/tmp/irlume-method-override"));
        std::env::remove_var("IRLUME_METHOD_CONF");
        assert_eq!(path(), PathBuf::from("/etc/irlume/method"));
    }

    #[test]
    fn method_reads_file_and_defaults_when_absent() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("irlume-policy-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("method");
        std::env::set_var("IRLUME_METHOD_CONF", &f);

        // Absent/unreadable file -> Auto.
        assert_eq!(method(), Method::Auto);

        std::fs::write(&f, "fingerprint\n").unwrap();
        assert_eq!(method(), Method::Fingerprint);
        std::fs::write(&f, "face").unwrap();
        assert_eq!(method(), Method::Face);

        std::env::remove_var("IRLUME_METHOD_CONF");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_method_persists_creates_parent_and_roundtrips() {
        let _g = crate::testenv::ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("irlume-policy-set-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Nested path: set_method must create the missing parent directory.
        let f = dir.join("nested/method");
        std::env::set_var("IRLUME_METHOD_CONF", &f);

        set_method(Method::Fingerprint).unwrap();
        assert!(f.exists());
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "fingerprint");
        assert_eq!(method(), Method::Fingerprint);

        set_method(Method::Auto).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "auto");
        assert_eq!(method(), Method::Auto);

        std::env::remove_var("IRLUME_METHOD_CONF");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
