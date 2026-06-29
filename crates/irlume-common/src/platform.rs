//! Per-distro abstraction. A minimal port of linhello's platform layer — just
//! the distro-family detection that the fingerprint (and, later, login) wiring
//! needs to pick the right mechanism (authselect vs pam-auth-update vs direct).

/// Distro family, for choosing the PAM-wiring mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistroFamily {
    /// Debian/Ubuntu/Mint — `pam-auth-update` + `/usr/share/pam-configs`.
    Debian,
    /// Fedora/RHEL/derivatives — `authselect` custom profiles.
    Fedora,
    /// Arch/Manjaro/EndeavourOS — edit `/etc/pam.d` services directly.
    Arch,
    /// Anything else — direct `/etc/pam.d` edits, best-effort.
    Other,
}

impl DistroFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            DistroFamily::Debian => "Debian-family",
            DistroFamily::Fedora => "Fedora-family",
            DistroFamily::Arch => "Arch-family",
            DistroFamily::Other => "other/unknown",
        }
    }
}

/// Detect the distro family from `/etc/os-release` (`ID` + `ID_LIKE`).
pub fn distro_family() -> DistroFamily {
    let os = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let field = |key: &str| -> String {
        os.lines()
            .find_map(|l| l.strip_prefix(key))
            .map(|v| v.trim().trim_matches('"').to_lowercase())
            .unwrap_or_default()
    };
    let id = field("ID=");
    let like = field("ID_LIKE=");
    let hay = format!("{id} {like}");
    if ["debian", "ubuntu", "mint", "pop", "raspbian"].iter().any(|d| hay.contains(d)) {
        DistroFamily::Debian
    } else if ["fedora", "rhel", "centos", "rocky", "alma"].iter().any(|d| hay.contains(d)) {
        DistroFamily::Fedora
    } else if ["arch", "manjaro", "endeavouros", "garuda"].iter().any(|d| hay.contains(d)) {
        DistroFamily::Arch
    } else {
        DistroFamily::Other
    }
}
