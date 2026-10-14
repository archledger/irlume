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

/// The image-security database of allowed signers (`db`).
const DB_VAR: &str = "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f";
/// The Key Exchange Key database, whose keys sign `db` and `dbx` updates.
const KEK_VAR: &str = "KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c";
/// `EFI_CERT_X509_GUID` (a5c059a1-94e4-4aa7-87b5-ab155c2bf072) as it is stored:
/// the first three fields little-endian.
const EFI_CERT_X509_GUID: [u8; 16] = [
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
];

/// `EFI_CERT_RSA2048_GUID` (3c5766e8-269c-4e34-aa14-ed776e85b3b6) as stored. Its
/// entries are a bare 2048-bit modulus, big-endian, with exponent 65537.
const EFI_CERT_RSA2048_GUID: [u8; 16] = [
    0xe8, 0x66, 0x57, 0x3c, 0x9c, 0x26, 0x34, 0x4e, 0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6,
];

/// The Microsoft KEKs a firmware may hold as a bare RSA-2048 key instead of a
/// certificate, which Microsoft's Secure Boot key guidance allows: SHA-256 of
/// the modulus of each certificate in microsoft/secureboot_objects
/// (PreSignedObjects/KEK/Certificates), with that certificate's subject.
const MICROSOFT_RSA_KEKS: [([u8; 32], &str); 2] = [
    (
        hex32("e8ff8556639b4a435958ecf65a36caa281c0da3d3b5ebafcad1a6d261bb6e15c"),
        "Microsoft Corporation KEK CA 2011",
    ),
    (
        hex32("f19c4ead7e9748b95b6281006d52858531095d5821a11f3392db3b51c97b79e9"),
        "Microsoft Corporation KEK 2K CA 2023",
    ),
];

/// A 64-digit hex string as 32 bytes, at compile time.
const fn hex32(text: &str) -> [u8; 32] {
    const fn digit(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not a lowercase hex digit"),
        }
    }
    let bytes = text.as_bytes();
    assert!(bytes.len() == 64);
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = digit(bytes[2 * i]) << 4 | digit(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

/// Microsoft's 2011 Secure Boot certificates, each with the 2023 certificate
/// that replaces it and the database both live in. The 2011 ones expire between
/// June and October 2026; Microsoft, OEM firmware and, on Linux, fwupd 2.0.8 and
/// later (from LVFS) enroll the replacements. The Microsoft UEFI CA 2011's other
/// successor, the Option ROM UEFI CA 2023, is left out: only machines whose
/// add-in cards need it get it.
const MICROSOFT_ROLLOVER: [(&str, &str, &str); 3] = [
    (
        "KEK",
        "Microsoft Corporation KEK CA 2011",
        "Microsoft Corporation KEK 2K CA 2023",
    ),
    (
        "db",
        "Microsoft Windows Production PCA 2011",
        "Windows UEFI CA 2023",
    ),
    (
        "db",
        "Microsoft Corporation UEFI CA 2011",
        "Microsoft UEFI CA 2023",
    ),
];

/// Where this machine's Secure Boot databases stand in Microsoft's 2026
/// certificate rollover. Enrolling the 2023 certificates rewrites `KEK` and
/// `db`, which PCR 7 measures, so a seal bound to PCR 7 stops opening after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateRollover {
    /// Not a UEFI boot: there are no Secure Boot databases.
    NotUefi,
    /// No `KEK` or `db` is enrolled (a platform in setup mode, keys cleared).
    NoKeys,
    /// `KEK` or `db` exists but could not be read, or both are absent outside
    /// setup mode (efivarfs unmounted, or empty databases in user mode).
    Unreadable,
    /// Every 2011 certificate enrolled here has its 2023 replacement.
    Updated,
    /// These 2023 certificates are still to be enrolled, each named with the
    /// database it belongs in.
    Pending(Vec<(&'static str, &'static str)>),
    /// No Microsoft 2011 certificate is enrolled: a machine with its own keys,
    /// which Microsoft's rollover does not update.
    NotMicrosoft,
}

/// Microsoft's 2026 Secure Boot certificate rollover on this machine.
pub fn certificate_rollover() -> CertificateRollover {
    certificate_rollover_in(Path::new(EFIVARS))
}

fn certificate_rollover_in(efivars: &Path) -> CertificateRollover {
    if !efivars.is_dir() {
        return CertificateRollover::NotUefi;
    }
    // An absent database holds no certificates; one that is there but does not
    // read is not known to be empty.
    let names = |name: &str| -> Option<Option<Vec<String>>> {
        if !efivar_exists_in(efivars, name) {
            return Some(None);
        }
        read_efivar_bytes_in(efivars, name).map(|b| Some(signer_names(&b)))
    };
    let (Some(kek), Some(db)) = (names(KEK_VAR), names(DB_VAR)) else {
        return CertificateRollover::Unreadable;
    };
    if kek.is_none() && db.is_none() {
        // No KEK or db at all proves nothing by itself: efivarfs may be
        // unmounted, or a platform in user mode may hold empty databases.
        // Only setup mode says no keys are enrolled.
        return if setup_mode_in(efivars) {
            CertificateRollover::NoKeys
        } else {
            CertificateRollover::Unreadable
        };
    }
    let (kek, db) = (kek.unwrap_or_default(), db.unwrap_or_default());
    let names = |database: &str| if database == "KEK" { &kek } else { &db };
    let mut microsoft = false;
    let mut pending = Vec::new();
    for (database, old, new) in MICROSOFT_ROLLOVER {
        let in_database = names(database);
        let has_new = in_database.iter().any(|n| n == new);
        // A machine provisioned after the 2011 certificates were withdrawn
        // holds only the 2023 ones: updated, not a machine with its own keys.
        microsoft |= has_new;
        if in_database.iter().any(|n| n == old) {
            microsoft = true;
            if !has_new {
                pending.push((database, new));
            }
        }
    }
    if !microsoft {
        CertificateRollover::NotMicrosoft
    } else if pending.is_empty() {
        CertificateRollover::Updated
    } else {
        CertificateRollover::Pending(pending)
    }
}

/// The signers in an EFI signature database: each X.509 certificate's subject
/// common name, and for each bare RSA-2048 key, the subject of the Microsoft
/// KEK certificate with that modulus ([`MICROSOFT_RSA_KEKS`]).
fn signer_names(data: &[u8]) -> Vec<String> {
    let mut names = x509_subject_names(data);
    names.extend(
        signature_entries(data, EFI_CERT_RSA2048_GUID).filter_map(|key| {
            use sha2::Digest as _;
            let digest: [u8; 32] = sha2::Sha256::digest(key).into();
            MICROSOFT_RSA_KEKS
                .iter()
                .find(|(known, _)| *known == digest)
                .map(|(_, name)| (*name).to_owned())
        }),
    );
    names
}

/// The data of each signature of type `kind` in an EFI signature database (a
/// run of `EFI_SIGNATURE_LIST`s), without its owner GUID. A list that does not
/// parse ends the walk.
fn signature_entries(mut data: &[u8], kind: [u8; 16]) -> impl Iterator<Item = &[u8]> {
    let mut entries = Vec::new();
    // EFI_SIGNATURE_LIST: SignatureType (16), SignatureListSize (4),
    // SignatureHeaderSize (4), SignatureSize (4), header, then signatures of
    // SignatureSize bytes each: SignatureOwner (16) and the signature data.
    while data.len() >= 28 {
        let le =
            |at: usize| u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);
        let (list_size, header_size, entry_size) =
            (le(16) as usize, le(20) as usize, le(24) as usize);
        if list_size < 28 || list_size > data.len() {
            break;
        }
        let (list, rest) = data.split_at(list_size);
        data = rest;
        if list[..16] != kind || entry_size <= 16 {
            continue;
        }
        if let Some(signatures) = list.get(28 + header_size..) {
            entries.extend(
                signatures
                    .chunks_exact(entry_size)
                    .map(|entry| &entry[16..]),
            );
        }
    }
    entries.into_iter()
}

/// The subject common names of the X.509 certificates in an EFI signature
/// database. Lists of other types and anything that does not parse are skipped.
fn x509_subject_names(data: &[u8]) -> Vec<String> {
    signature_entries(data, EFI_CERT_X509_GUID)
        .filter_map(certificate_subject_cn)
        .collect()
}

/// One DER element: its tag, its contents and what follows it.
fn der_element(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let len = rest[..count]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (len, &rest[count..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// The subject commonName of a DER X.509 certificate.
fn certificate_subject_cn(cert: &[u8]) -> Option<String> {
    const SEQUENCE: u8 = 0x30;
    let (SEQUENCE, certificate, _) = der_element(cert)? else {
        return None;
    };
    let (SEQUENCE, tbs, _) = der_element(certificate)? else {
        return None;
    };
    // tbsCertificate: [0] version (optional), serialNumber, signature,
    // issuer, validity, subject.
    let (tag, _, mut rest) = der_element(tbs)?;
    if tag != 0xa0 {
        rest = tbs;
    }
    for _ in 0..4 {
        rest = der_element(rest)?.2;
    }
    let (SEQUENCE, mut rdns, _) = der_element(rest)? else {
        return None;
    };
    // Name: SET OF AttributeTypeAndValue { type OID, value }.
    const COMMON_NAME: [u8; 3] = [0x55, 0x04, 0x03];
    while let Some((_, set, next)) = der_element(rdns) {
        let mut attributes = set;
        while let Some((_, attribute, after)) = der_element(attributes) {
            if let Some((0x06, oid, value)) = der_element(attribute) {
                if oid == COMMON_NAME {
                    let (_, text, _) = der_element(value)?;
                    return String::from_utf8(text.to_vec()).ok();
                }
            }
            attributes = after;
        }
        rdns = next;
    }
    None
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

    /// One DER element, with the long length form when the contents need it.
    fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = contents.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
        }
        out.extend_from_slice(contents);
        out
    }

    /// A Name holding one organization and one commonName, as Microsoft's are.
    fn name(cn: &str) -> Vec<u8> {
        let attribute = |oid: &[u8], text: &str| {
            der(
                0x31,
                &der(0x30, &[der(0x06, oid), der(0x13, text.as_bytes())].concat()),
            )
        };
        der(
            0x30,
            &[
                attribute(&[0x55, 0x04, 0x0a], "Microsoft Corporation"),
                attribute(&[0x55, 0x04, 0x03], cn),
            ]
            .concat(),
        )
    }

    /// A certificate whose issuer and subject differ, so a parser that read
    /// the issuer would name the wrong certificate.
    fn certificate(subject: &str) -> Vec<u8> {
        let algorithm = der(
            0x30,
            &der(
                0x06,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
            ),
        );
        let tbs = der(
            0x30,
            &[
                der(0xa0, &der(0x02, &[2])),
                der(0x02, &[0x33, 0x01]),
                algorithm.clone(),
                name("Microsoft RSA Devices Root CA 2021"),
                der(
                    0x30,
                    &[der(0x17, b"230101000000Z"), der(0x17, b"380101000000Z")].concat(),
                ),
                name(subject),
                der(0x30, &[0u8; 200]),
            ]
            .concat(),
        );
        der(0x30, &[tbs, algorithm, der(0x03, &[0, 1, 2, 3])].concat())
    }

    /// One EFI_SIGNATURE_LIST of `kind` holding `entries` (owner GUID + data,
    /// all the same size, as the format requires).
    fn signature_list(kind: [u8; 16], entries: &[Vec<u8>]) -> Vec<u8> {
        let entry_size = 16 + entries.first().map_or(0, Vec::len);
        let size = 28 + entry_size * entries.len();
        let mut out = kind.to_vec();
        for field in [size, 0, entry_size] {
            out.extend_from_slice(&(field as u32).to_le_bytes());
        }
        for entry in entries {
            out.extend_from_slice(&[0x77; 16]);
            out.extend_from_slice(entry);
        }
        out
    }

    fn database(certificates: &[&str]) -> Vec<u8> {
        let sha256_guid = [
            0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93,
            0x43, 0x28,
        ];
        let mut out = signature_list(sha256_guid, &[vec![0xab; 32], vec![0xcd; 32]]);
        for cn in certificates {
            out.extend(signature_list(EFI_CERT_X509_GUID, &[certificate(cn)]));
        }
        out
    }

    #[test]
    fn signature_databases_yield_their_certificate_subjects() {
        let data = database(&["Windows UEFI CA 2023", "Microsoft UEFI CA 2023"]);
        assert_eq!(
            x509_subject_names(&data),
            ["Windows UEFI CA 2023", "Microsoft UEFI CA 2023"],
            "subjects in order, hash lists skipped, never the issuer"
        );
        let mut truncated = data.clone();
        truncated.truncate(data.len() - 40);
        assert_eq!(
            x509_subject_names(&truncated),
            ["Windows UEFI CA 2023"],
            "a list that runs past the end is not read"
        );
        assert!(x509_subject_names(&[0xff; 27]).is_empty());
        assert!(x509_subject_names(&[]).is_empty());
    }

    /// The modulus of Microsoft Corporation KEK 2K CA 2023
    /// (microsoft/secureboot_objects, PreSignedObjects/KEK/Certificates).
    fn kek_2023_modulus() -> Vec<u8> {
        let text: String = [
            "e35e888b732cc30ac4e9f5ce812df10ff1263537d1495371b15b9352afe115df",
            "de8b39bdaf4c657553e5da0a32982f3326b62bbe94999fecdac28e053492130f",
            "63bf74a272a8297e9f3221290859c477c42a924c87b60337eb9ae2c3c9b44821",
            "c36194ea1751b1e714e224632ed5f2c6a5f2a25e1f69c6510da729fb520a9be3",
            "88e868ffbbfa9269afc416ff5de55fe0dfec66550b61c2ac3b206edfb40deb2b",
            "c8d0c2344e829639eef13185043defd676fbc3cac1d58c2f0b10289b489ab010",
            "14a4d994e5685bcd6ee77aecbca049b8a953d84d2fb27bc8dabcb2e7fcab7010",
            "77954549fdadd23f17cb669af27d36dd0a2ce2c087212d93db0896d2e85c54e1",
        ]
        .concat();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn a_kek_held_as_a_bare_rsa_key_is_named_by_its_modulus() {
        let modulus = kek_2023_modulus();
        assert_eq!(modulus.len(), 256);
        let mut kek = database(&["Microsoft Corporation KEK CA 2011"]);
        kek.extend(signature_list(EFI_CERT_RSA2048_GUID, &[modulus.clone()]));
        assert_eq!(
            signer_names(&kek),
            [
                "Microsoft Corporation KEK CA 2011",
                "Microsoft Corporation KEK 2K CA 2023"
            ]
        );
        let mut altered = modulus;
        altered[0] ^= 1;
        assert!(
            signer_names(&signature_list(EFI_CERT_RSA2048_GUID, &[altered])).is_empty(),
            "an unknown key names nothing"
        );

        let dir = scratch("rsa-kek");
        write_var(&dir, KEK_VAR, &kek);
        write_var(
            &dir,
            DB_VAR,
            &database(&[
                "Microsoft Windows Production PCA 2011",
                "Windows UEFI CA 2023",
            ]),
        );
        assert_eq!(certificate_rollover_in(&dir), CertificateRollover::Updated);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_machine_with_only_the_2023_certificates_is_updated() {
        let dir = scratch("only-2023");
        write_var(
            &dir,
            KEK_VAR,
            &database(&["OEM KEK", "Microsoft Corporation KEK 2K CA 2023"]),
        );
        write_var(
            &dir,
            DB_VAR,
            &database(&["Windows UEFI CA 2023", "Microsoft UEFI CA 2023"]),
        );
        assert_eq!(certificate_rollover_in(&dir), CertificateRollover::Updated);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_2026_rollover_is_read_from_kek_and_db() {
        let dir = scratch("rollover");
        assert_eq!(
            certificate_rollover_in(&dir.join("absent")),
            CertificateRollover::NotUefi
        );
        assert_eq!(
            certificate_rollover_in(&dir),
            CertificateRollover::Unreadable,
            "no variables at all: efivarfs may be unmounted"
        );
        write_var(&dir, SETUPMODE_VAR, &[0]);
        assert_eq!(
            certificate_rollover_in(&dir),
            CertificateRollover::Unreadable,
            "empty databases in user mode are not proof of no keys"
        );
        write_var(&dir, SETUPMODE_VAR, &[1]);
        assert_eq!(
            certificate_rollover_in(&dir),
            CertificateRollover::NoKeys,
            "setup mode, as on archhost and minihost: no KEK or db at all"
        );

        let kek_2011 = database(&[
            "ASUSTeK Notebook KEK Certificate",
            "Microsoft Corporation KEK CA 2011",
        ]);
        let db_2011 = database(&[
            "Microsoft Windows Production PCA 2011",
            "Microsoft Corporation UEFI CA 2011",
        ]);
        write_var(&dir, KEK_VAR, &kek_2011);
        assert_eq!(
            certificate_rollover_in(&dir),
            CertificateRollover::Pending(vec![("KEK", "Microsoft Corporation KEK 2K CA 2023")]),
            "an absent db holds nothing to replace"
        );
        std::fs::write(dir.join(DB_VAR), [0x07]).unwrap();
        assert_eq!(
            certificate_rollover_in(&dir),
            CertificateRollover::Unreadable,
            "a db that is there but does not read is not taken as empty"
        );
        write_var(&dir, DB_VAR, &db_2011);
        assert_eq!(
            certificate_rollover_in(&dir),
            CertificateRollover::Pending(vec![
                ("KEK", "Microsoft Corporation KEK 2K CA 2023"),
                ("db", "Windows UEFI CA 2023"),
                ("db", "Microsoft UEFI CA 2023"),
            ])
        );

        // A 2023 name in the wrong database does not count.
        write_var(
            &dir,
            KEK_VAR,
            &database(&["Microsoft Corporation KEK CA 2011", "Windows UEFI CA 2023"]),
        );
        write_var(
            &dir,
            DB_VAR,
            &database(&[
                "Microsoft Windows Production PCA 2011",
                "Microsoft Corporation UEFI CA 2011",
                "Windows UEFI CA 2023",
                "Microsoft UEFI CA 2023",
                "Microsoft Corporation KEK 2K CA 2023",
            ]),
        );
        assert_eq!(
            certificate_rollover_in(&dir),
            CertificateRollover::Pending(vec![("KEK", "Microsoft Corporation KEK 2K CA 2023")])
        );

        write_var(
            &dir,
            KEK_VAR,
            &database(&[
                "Microsoft Corporation KEK CA 2011",
                "Microsoft Corporation KEK 2K CA 2023",
            ]),
        );
        assert_eq!(certificate_rollover_in(&dir), CertificateRollover::Updated);

        // A Windows-only db needs only the Windows replacement.
        write_var(
            &dir,
            DB_VAR,
            &database(&[
                "Microsoft Windows Production PCA 2011",
                "Windows UEFI CA 2023",
            ]),
        );
        assert_eq!(certificate_rollover_in(&dir), CertificateRollover::Updated);

        write_var(&dir, KEK_VAR, &database(&["Owner KEK"]));
        write_var(&dir, DB_VAR, &database(&["Owner db"]));
        assert_eq!(
            certificate_rollover_in(&dir),
            CertificateRollover::NotMicrosoft
        );
        let _ = std::fs::remove_dir_all(&dir);
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
