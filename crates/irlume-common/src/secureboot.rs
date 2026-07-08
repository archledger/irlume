//! Boot-mode and Secure Boot detection via Linux efivarfs + procfs.
//!
//! Best-effort and never panics: on a non-EFI system, missing efivars, or
//! unreadable files we return conservative defaults. Shared so the daemon and
//! `doctor` agree (and so the daemon can gate on the *real* Secure Boot state).

use std::fs;
use std::path::Path;

/// How the system booted — informs which TPM PCR-binding tier is meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    /// Unified Kernel Image (systemd-stub) — eligible for signed PCR-11 policy.
    Uki,
    /// GRUB / systemd-boot / traditional loader — uses self-healing PCR-7.
    Grub,
    /// Couldn't determine.
    Unknown,
}

impl BootMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            BootMode::Uki => "UKI (signed PCR-11 eligible)",
            BootMode::Grub => "GRUB/loader (self-healing PCR-7)",
            BootMode::Unknown => "unknown bootloader",
        }
    }
}

const EFI_ROOT: &str = "/sys/firmware/efi";
const EFIVARS: &str = "/sys/firmware/efi/efivars";

/// Global EFI SecureBoot variable.
const SECUREBOOT_VAR: &str = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
/// `SetupMode` — when 1, platform keys are not enrolled (SB not enforcing).
const SETUPMODE_VAR: &str = "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c";
/// systemd-stub writes this when a UKI is booted (Loader interface GUID).
const STUB_INFO_VAR: &str = "StubInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";
/// systemd-boot writes this when it is the active loader.
const LOADER_INFO_VAR: &str = "LoaderInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

/// UEFI? and if so, UKI vs traditional loader.
pub fn detect_boot_mode() -> BootMode {
    if !Path::new(EFI_ROOT).exists() {
        return BootMode::Grub;
    }
    if efivar_exists(STUB_INFO_VAR) {
        return BootMode::Uki;
    }
    if efivar_exists(LOADER_INFO_VAR) || grub_artifacts_present() {
        return BootMode::Grub;
    }
    BootMode::Unknown
}

/// True when firmware is in SetupMode (no platform keys enrolled). In this
/// state SecureBoot==1 does NOT mean Secure Boot is enforcing.
pub fn is_setup_mode() -> bool {
    matches!(read_efivar_u8(SETUPMODE_VAR), Some(1))
}

/// True when UEFI Secure Boot is actually enforcing: SecureBoot==1 AND not in
/// SetupMode. (Reporting only SecureBoot==1 gives a false trust signal when the
/// platform is in setup mode and any key can be enrolled.)
pub fn is_secure_boot_enabled() -> bool {
    let Some(secure) = read_efivar_u8(SECUREBOOT_VAR) else {
        return false;
    };
    let setup = read_efivar_u8(SETUPMODE_VAR).unwrap_or(0);
    secure == 1 && setup == 0
}

/// Whether the SecureBoot efivar is readable at all (UEFI boot).
pub fn secure_boot_present() -> bool {
    read_efivar_u8(SECUREBOOT_VAR).is_some()
}

/// Best-effort active boot loader / stub name.
pub fn loader_identity() -> Option<String> {
    read_efivar_utf16(STUB_INFO_VAR).or_else(|| read_efivar_utf16(LOADER_INFO_VAR))
}

fn efivar_exists(name: &str) -> bool {
    Path::new(EFIVARS).join(name).exists()
}

fn read_efivar_bytes(name: &str) -> Option<Vec<u8>> {
    let bytes = fs::read(Path::new(EFIVARS).join(name)).ok()?;
    // First 4 bytes are UEFI variable attributes; strip them.
    if bytes.len() < 5 {
        return None;
    }
    Some(bytes[4..].to_vec())
}

fn read_efivar_u8(name: &str) -> Option<u8> {
    read_efivar_bytes(name).and_then(|b| b.first().copied())
}

fn read_efivar_utf16(name: &str) -> Option<String> {
    let data = read_efivar_bytes(name)?;
    if data.len() < 2 {
        return None;
    }
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16(&u16s).ok()
}

fn grub_artifacts_present() -> bool {
    [
        "/boot/grub/grub.cfg",
        "/boot/grub2/grub.cfg",
        "/etc/default/grub",
    ]
    .iter()
    .any(|p| Path::new(p).exists())
}
