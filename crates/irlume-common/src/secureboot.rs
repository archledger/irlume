// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Boot-mode and Secure Boot detection via Linux efivarfs + procfs.
//!
//! Best-effort and never panics: on a non-EFI system, missing efivars, or
//! unreadable files we return conservative defaults. Shared so the daemon and
//! `doctor` agree (and so the daemon can gate on the *real* Secure Boot state).
//!
//! The public functions read the fixed system paths; each delegates to an
//! `_at`/`_in` twin parameterized on the efivars directory (test seam: the
//! parsing runs against fixture files in a tempdir; behavior unchanged).

use std::fs;
use std::path::Path;

/// How the system booted; informs which TPM PCR-binding tier is meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    /// Unified Kernel Image (systemd-stub); eligible for signed PCR-11 policy.
    Uki,
    /// GRUB / systemd-boot / traditional loader; uses self-healing PCR-7.
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
/// `SetupMode`: when 1, platform keys are not enrolled (SB not enforcing).
const SETUPMODE_VAR: &str = "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c";
/// systemd-stub writes this when a UKI is booted (Loader interface GUID).
const STUB_INFO_VAR: &str = "StubInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";
/// systemd-boot writes this when it is the active loader.
const LOADER_INFO_VAR: &str = "LoaderInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";

/// UEFI? and if so, UKI vs traditional loader.
pub fn detect_boot_mode() -> BootMode {
    detect_boot_mode_at(
        Path::new(EFI_ROOT),
        Path::new(EFIVARS),
        grub_artifacts_present(),
    )
}

fn detect_boot_mode_at(efi_root: &Path, efivars: &Path, grub_present: bool) -> BootMode {
    if !efi_root.exists() {
        return BootMode::Grub;
    }
    if efivar_exists_in(efivars, STUB_INFO_VAR) {
        return BootMode::Uki;
    }
    if efivar_exists_in(efivars, LOADER_INFO_VAR) || grub_present {
        return BootMode::Grub;
    }
    BootMode::Unknown
}

/// True when firmware is in SetupMode (no platform keys enrolled). In this
/// state SecureBoot==1 does NOT mean Secure Boot is enforcing.
pub fn is_setup_mode() -> bool {
    setup_mode_in(Path::new(EFIVARS))
}

fn setup_mode_in(efivars: &Path) -> bool {
    matches!(read_efivar_u8_in(efivars, SETUPMODE_VAR), Some(1))
}

/// True when UEFI Secure Boot is actually enforcing: SecureBoot==1 AND not in
/// SetupMode. (Reporting only SecureBoot==1 gives a false trust signal when the
/// platform is in setup mode and any key can be enrolled.)
pub fn is_secure_boot_enabled() -> bool {
    secure_boot_enabled_in(Path::new(EFIVARS))
}

fn secure_boot_enabled_in(efivars: &Path) -> bool {
    let Some(secure) = read_efivar_u8_in(efivars, SECUREBOOT_VAR) else {
        return false;
    };
    let setup = read_efivar_u8_in(efivars, SETUPMODE_VAR).unwrap_or(0);
    secure == 1 && setup == 0
}

/// Whether the SecureBoot efivar is readable at all (UEFI boot).
pub fn secure_boot_present() -> bool {
    secure_boot_present_in(Path::new(EFIVARS))
}

fn secure_boot_present_in(efivars: &Path) -> bool {
    read_efivar_u8_in(efivars, SECUREBOOT_VAR).is_some()
}

/// Best-effort active boot loader / stub name.
pub fn loader_identity() -> Option<String> {
    loader_identity_in(Path::new(EFIVARS))
}

fn loader_identity_in(efivars: &Path) -> Option<String> {
    read_efivar_utf16_in(efivars, STUB_INFO_VAR)
        .or_else(|| read_efivar_utf16_in(efivars, LOADER_INFO_VAR))
}

fn efivar_exists_in(efivars: &Path, name: &str) -> bool {
    efivars.join(name).exists()
}

fn read_efivar_bytes_in(efivars: &Path, name: &str) -> Option<Vec<u8>> {
    let bytes = fs::read(efivars.join(name)).ok()?;
    // First 4 bytes are UEFI variable attributes; strip them.
    if bytes.len() < 5 {
        return None;
    }
    Some(bytes[4..].to_vec())
}

fn read_efivar_u8_in(efivars: &Path, name: &str) -> Option<u8> {
    read_efivar_bytes_in(efivars, name).and_then(|b| b.first().copied())
}

fn read_efivar_utf16_in(efivars: &Path, name: &str) -> Option<String> {
    let data = read_efivar_bytes_in(efivars, name)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A scratch efivars directory. Fixture layout mirrors the kernel's
    /// efivarfs: 4 little-endian attribute bytes, then the variable value.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("irlume-sb-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Write an efivar fixture: attrs prefix 0x07,0,0,0 (NV+BS+RT) + value.
    fn write_var(dir: &Path, name: &str, value: &[u8]) {
        let mut bytes = vec![0x07, 0, 0, 0];
        bytes.extend_from_slice(value);
        std::fs::write(dir.join(name), bytes).unwrap();
    }

    #[test]
    fn secure_boot_enabled_requires_sb1_and_not_setup_mode() {
        let dir = scratch("enabled");
        // SecureBoot=1, no SetupMode var at all (missing reads as 0): enforcing.
        write_var(&dir, SECUREBOOT_VAR, &[1]);
        assert!(secure_boot_present_in(&dir));
        assert!(secure_boot_enabled_in(&dir));
        assert!(!setup_mode_in(&dir));
        // SetupMode=0 explicit: still enforcing.
        write_var(&dir, SETUPMODE_VAR, &[0]);
        assert!(secure_boot_enabled_in(&dir));
        // SetupMode=1: SecureBoot=1 is a false trust signal; must report OFF.
        write_var(&dir, SETUPMODE_VAR, &[1]);
        assert!(setup_mode_in(&dir));
        assert!(!secure_boot_enabled_in(&dir), "setup mode must veto SB=1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn secure_boot_disabled_and_absent_cases() {
        let dir = scratch("disabled");
        // SecureBoot=0: present but not enforcing.
        write_var(&dir, SECUREBOOT_VAR, &[0]);
        assert!(secure_boot_present_in(&dir));
        assert!(!secure_boot_enabled_in(&dir));
        let _ = std::fs::remove_dir_all(&dir);

        // No efivars at all (legacy BIOS boot): absent, off, not setup mode.
        let empty = scratch("absent");
        assert!(!secure_boot_present_in(&empty));
        assert!(!secure_boot_enabled_in(&empty));
        assert!(!setup_mode_in(&empty));
        let _ = std::fs::remove_dir_all(&empty);
    }

    #[test]
    fn truncated_efivar_yields_none_not_garbage() {
        let dir = scratch("short");
        // Attrs-only file (4 bytes): no value byte to read.
        std::fs::write(dir.join(SECUREBOOT_VAR), [0x07, 0, 0, 0]).unwrap();
        assert_eq!(read_efivar_u8_in(&dir, SECUREBOOT_VAR), None);
        assert!(!secure_boot_present_in(&dir));
        // Empty file.
        std::fs::write(dir.join(SETUPMODE_VAR), []).unwrap();
        assert_eq!(read_efivar_u8_in(&dir, SETUPMODE_VAR), None);
        assert!(!setup_mode_in(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn loader_identity_decodes_utf16le_and_prefers_the_stub() {
        let dir = scratch("loader");
        let utf16 = |s: &str, nul_terminated: bool| -> Vec<u8> {
            let mut v: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
            if nul_terminated {
                v.extend_from_slice(&[0, 0]);
                // Trailing garbage after the terminator must be ignored.
                v.extend_from_slice(&[0x41, 0x00]);
            }
            v
        };
        // LoaderInfo alone.
        write_var(&dir, LOADER_INFO_VAR, &utf16("systemd-boot 257.6", true));
        assert_eq!(
            loader_identity_in(&dir).as_deref(),
            Some("systemd-boot 257.6")
        );
        // StubInfo present too: the stub name wins (a UKI boot chains through
        // systemd-boot, but the stub is what measured the kernel).
        write_var(&dir, STUB_INFO_VAR, &utf16("systemd-stub 257.6", false));
        assert_eq!(
            loader_identity_in(&dir).as_deref(),
            Some("systemd-stub 257.6")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn loader_identity_rejects_undecodable_values() {
        let dir = scratch("badloader");
        // One byte of value after attrs: too short for a UTF-16 unit.
        write_var(&dir, LOADER_INFO_VAR, &[0x41]);
        assert_eq!(loader_identity_in(&dir), None);
        // An unpaired UTF-16 surrogate (0xD800) cannot decode.
        write_var(&dir, LOADER_INFO_VAR, &0xD800u16.to_le_bytes());
        assert_eq!(loader_identity_in(&dir), None);
        // Odd trailing byte: chunks_exact drops it; the rest still decodes.
        let mut odd: Vec<u8> = "ok".encode_utf16().flat_map(u16::to_le_bytes).collect();
        odd.push(0x00);
        write_var(&dir, STUB_INFO_VAR, &odd);
        assert_eq!(loader_identity_in(&dir).as_deref(), Some("ok"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn boot_mode_detection_orders_stub_loader_grub_unknown() {
        let no_efi = scratch("noefi-root").join("missing");
        let efivars = scratch("bootmode");
        let efi_root = std::env::temp_dir(); // any existing dir stands in for /sys/firmware/efi

        // No EFI root: legacy boot, GRUB regardless of grub_present.
        assert_eq!(
            detect_boot_mode_at(&no_efi, &efivars, false),
            BootMode::Grub
        );
        // EFI, no loader vars, no grub artifacts: Unknown.
        assert_eq!(
            detect_boot_mode_at(&efi_root, &efivars, false),
            BootMode::Unknown
        );
        // EFI + grub artifacts on disk: Grub.
        assert_eq!(
            detect_boot_mode_at(&efi_root, &efivars, true),
            BootMode::Grub
        );
        // EFI + LoaderInfo (systemd-boot, non-UKI): Grub-tier.
        write_var(&efivars, LOADER_INFO_VAR, &[0x41, 0x00]);
        assert_eq!(
            detect_boot_mode_at(&efi_root, &efivars, false),
            BootMode::Grub
        );
        // StubInfo present: UKI wins over everything else.
        write_var(&efivars, STUB_INFO_VAR, &[0x41, 0x00]);
        assert_eq!(
            detect_boot_mode_at(&efi_root, &efivars, true),
            BootMode::Uki
        );
        let _ = std::fs::remove_dir_all(&efivars);
    }

    #[test]
    fn boot_mode_as_str_names_each_mode() {
        assert_eq!(BootMode::Uki.as_str(), "UKI (signed PCR-11 eligible)");
        assert_eq!(BootMode::Grub.as_str(), "GRUB/loader (self-healing PCR-7)");
        assert_eq!(BootMode::Unknown.as_str(), "unknown bootloader");
    }

    #[test]
    fn host_wrappers_are_consistent_with_each_other() {
        // Read-only probes of the real /sys; the values vary by box, but the
        // invariants cannot: enforcing implies the var is present, and a
        // present-and-enforcing state excludes setup mode.
        let present = secure_boot_present();
        let enabled = is_secure_boot_enabled();
        let setup = is_setup_mode();
        if enabled {
            assert!(
                present,
                "enforcing Secure Boot implies a readable SecureBoot var"
            );
            assert!(!setup, "enforcing Secure Boot excludes setup mode");
        }
        // detect_boot_mode + loader_identity must never panic; a decoded
        // loader name is never the empty string (the first UTF-16 unit of a
        // real StubInfo/LoaderInfo value is printable, not NUL).
        let _ = detect_boot_mode();
        if let Some(name) = loader_identity() {
            assert!(!name.is_empty());
        }
    }
}
