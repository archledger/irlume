// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! The firmware's TCG event log, in the crypto-agile format of the TCG PC
//! Client Platform Firmware Profile, as the kernel exposes it at
//! `/sys/kernel/security/tpm0/binary_bios_measurements`: enough of it to say
//! what PCR 7 binds. Firmware writes the log, but some event data (device
//! paths, option ROM descriptions) comes from devices, so every length is
//! checked and nothing here panics on any input (the `event_log` fuzz target).

/// Where the kernel exposes the log (root only).
pub const EVENT_LOG: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";

const EV_NO_ACTION: u32 = 0x0000_0003;
const EV_SEPARATOR: u32 = 0x0000_0004;
const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = 0x8000_0001;
const EV_EFI_ACTION: u32 = 0x8000_0007;
const EV_EFI_VARIABLE_AUTHORITY: u32 = 0x8000_00e0;

/// The signature that opens the first event of a crypto-agile log.
const SPEC_ID_EVENT03: &[u8; 16] = b"Spec ID Event03\0";
/// More events than any firmware writes; a longer log is not read further.
const MAX_EVENTS: usize = 100_000;

/// One event of the log: its PCR, its type and its event data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event<'a> {
    pub pcr: u32,
    pub kind: u32,
    pub data: &'a [u8],
}

/// Little-endian readers over a shrinking slice.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }
}

/// The events of a crypto-agile log, from the first event after the Spec ID
/// header. `None` when the log does not open with a Spec ID Event03 header
/// (a SHA-1-only log, or not an event log at all). An event that runs past
/// the end, or uses a digest algorithm the header did not declare, ends the
/// list there: `complete` is then false.
pub fn events(log: &[u8]) -> Option<(Vec<Event<'_>>, bool)> {
    let mut r = Reader(log);
    // The header is a TCG_PCR_EVENT: PCR, type, a SHA-1 digest, then the
    // Spec ID event data.
    let (_pcr, kind) = (r.u32()?, r.u32()?);
    r.take(20)?;
    let size = r.u32()? as usize;
    let mut spec = Reader(r.take(size)?);
    if kind != EV_NO_ACTION || spec.take(16)? != SPEC_ID_EVENT03 {
        return None;
    }
    // platformClass, specVersionMinor/Major, specErrata, uintnSize.
    spec.take(8)?;
    let count = spec.u32()?;
    let mut sizes = Vec::new();
    for _ in 0..count.min(64) {
        sizes.push((spec.u16()?, usize::from(spec.u16()?)));
    }
    let mut out = Vec::new();
    while !r.0.is_empty() {
        if out.len() >= MAX_EVENTS {
            return Some((out, false));
        }
        let Some(event) = event2(&mut r, &sizes) else {
            return Some((out, false));
        };
        out.push(event);
    }
    Some((out, true))
}

/// One TCG_PCR_EVENT2: PCR, type, a digest per algorithm, then the event data.
fn event2<'a>(r: &mut Reader<'a>, sizes: &[(u16, usize)]) -> Option<Event<'a>> {
    let (pcr, kind, count) = (r.u32()?, r.u32()?, r.u32()?);
    for _ in 0..count {
        let algorithm = r.u16()?;
        let size = sizes.iter().find(|(id, _)| *id == algorithm)?.1;
        r.take(size)?;
    }
    let size = r.u32()? as usize;
    Some(Event {
        pcr,
        kind,
        data: r.take(size)?,
    })
}

/// A UEFI_VARIABLE_DATA event: the variable's name and its data. The vendor
/// GUID is not kept.
fn variable(data: &[u8]) -> Option<(String, &[u8])> {
    let mut r = Reader(data);
    r.take(16)?;
    let name_len = usize::try_from(r.u64()?).ok()?;
    let data_len = usize::try_from(r.u64()?).ok()?;
    let name = r.take(name_len.checked_mul(2)?)?;
    let name: Vec<u16> = name
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some((String::from_utf16(&name).ok()?, r.take(data_len)?))
}

/// An authority measured into PCR 7: the variable that held what verified an
/// image (`db`, shim's `MokListRT`, its built-in certificate as `Shim`, or
/// shim's `SbatLevel`) and the signature data it measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority<'a> {
    pub variable: String,
    pub data: &'a [u8],
}

/// What PCR 7 recorded in this boot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pcr7<'a> {
    /// The SecureBoot variable as measured: `Some(true)` when it was 1.
    pub secure_boot: Option<bool>,
    /// The Secure Boot configuration variables measured (SecureBoot, PK,
    /// KEK, db, dbx, and any others), in order.
    pub configuration: Vec<String>,
    /// Whether the separator that ends the configuration was measured.
    pub separator: bool,
    /// The authorities that verified images, in order.
    pub authorities: Vec<Authority<'a>>,
    /// EV_EFI_ACTION strings, such as "UEFI Debug Mode" and "DMA Protection
    /// Disabled", which the firmware measures when it runs that way.
    pub actions: Vec<String>,
}

/// The PCR 7 events of `events`, read into [`Pcr7`]. Events that do not parse
/// are skipped.
pub fn pcr7<'a>(events: &[Event<'a>]) -> Pcr7<'a> {
    let mut out = Pcr7::default();
    for event in events.iter().filter(|e| e.pcr == 7) {
        match event.kind {
            EV_EFI_VARIABLE_DRIVER_CONFIG => {
                if let Some((name, data)) = variable(event.data) {
                    if name == "SecureBoot" {
                        out.secure_boot = data.first().map(|&v| v == 1);
                    }
                    out.configuration.push(name);
                }
            }
            EV_SEPARATOR => out.separator = true,
            EV_EFI_VARIABLE_AUTHORITY => {
                if let Some((variable, data)) = variable(event.data) {
                    out.authorities.push(Authority { variable, data });
                }
            }
            EV_EFI_ACTION => out
                .actions
                .push(String::from_utf8_lossy(event.data).into_owned()),
            _ => {}
        }
    }
    out
}

/// The certificate an authority from `db` measured: its EFI_SIGNATURE_DATA is
/// the owner GUID followed by the certificate.
pub fn authority_certificate<'a>(authority: &Authority<'a>) -> Option<&'a [u8]> {
    authority.data.get(16..).filter(|c| !c.is_empty())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A crypto-agile log: the Spec ID header declaring SHA-1 and SHA-256,
    /// then `events` as (PCR, type, data), each with both digests zeroed.
    pub(crate) fn log(events: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut spec = SPEC_ID_EVENT03.to_vec();
        spec.extend_from_slice(&[0, 0, 0, 0, 0, 2, 0, 2]);
        spec.extend_from_slice(&2u32.to_le_bytes());
        for (id, size) in [(0x0004u16, 20u16), (0x000b, 32)] {
            spec.extend_from_slice(&id.to_le_bytes());
            spec.extend_from_slice(&size.to_le_bytes());
        }
        spec.push(0);
        let mut out = Vec::new();
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&EV_NO_ACTION.to_le_bytes());
        out.extend_from_slice(&[0; 20]);
        out.extend_from_slice(&(spec.len() as u32).to_le_bytes());
        out.extend_from_slice(&spec);
        for (pcr, kind, data) in events {
            out.extend_from_slice(&pcr.to_le_bytes());
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&2u32.to_le_bytes());
            out.extend_from_slice(&0x0004u16.to_le_bytes());
            out.extend_from_slice(&[0; 20]);
            out.extend_from_slice(&0x000bu16.to_le_bytes());
            out.extend_from_slice(&[0; 32]);
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    /// UEFI_VARIABLE_DATA for `name` holding `data`.
    pub(crate) fn var(name: &str, data: &[u8]) -> Vec<u8> {
        let name: Vec<u16> = name.encode_utf16().collect();
        let mut out = vec![0x61; 16];
        out.extend_from_slice(&(name.len() as u64).to_le_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        for unit in name {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out.extend_from_slice(data);
        out
    }

    /// PCR 7 as this laptop's firmware and shim measure it (2026-10-15).
    pub(crate) fn shim_boot(db_certificate: &[u8], actions: &[&str]) -> Vec<u8> {
        let mut events = vec![
            (0, 0x0000_0008, b"S-CRTM".to_vec()),
            (7, EV_EFI_VARIABLE_DRIVER_CONFIG, var("SecureBoot", &[1])),
        ];
        for name in ["PK", "KEK", "db", "dbx"] {
            events.push((7, EV_EFI_VARIABLE_DRIVER_CONFIG, var(name, &[0x30; 40])));
        }
        for action in actions {
            events.push((7, EV_EFI_ACTION, action.as_bytes().to_vec()));
        }
        events.push((7, EV_SEPARATOR, vec![0; 4]));
        let mut signature = vec![0x77; 16];
        signature.extend_from_slice(db_certificate);
        events.push((7, EV_EFI_VARIABLE_AUTHORITY, var("db", &signature)));
        events.push((
            7,
            EV_EFI_VARIABLE_AUTHORITY,
            var("SbatLevel", b"sbat,1,2024010900\n"),
        ));
        events.push((7, EV_EFI_VARIABLE_AUTHORITY, var("MokListRT", &[0x30; 64])));
        events.push((4, 0x8000_0003, vec![1; 40]));
        log(&events)
    }

    #[test]
    fn a_shim_boot_reads_as_its_firmware_measured_it() {
        let data = shim_boot(b"certificate", &[]);
        let (events, complete) = events(&data).expect("a crypto-agile log");
        assert!(complete);
        assert_eq!(events.len(), 11);
        let pcr7 = pcr7(&events);
        assert_eq!(pcr7.secure_boot, Some(true));
        assert_eq!(pcr7.configuration, ["SecureBoot", "PK", "KEK", "db", "dbx"]);
        assert!(pcr7.separator);
        let names: Vec<&str> = pcr7
            .authorities
            .iter()
            .map(|a| a.variable.as_str())
            .collect();
        assert_eq!(names, ["db", "SbatLevel", "MokListRT"]);
        assert_eq!(
            authority_certificate(&pcr7.authorities[0]),
            Some(&b"certificate"[..])
        );
        assert!(pcr7.actions.is_empty());
    }

    #[test]
    fn firmware_actions_in_pcr_7_are_kept() {
        let data = shim_boot(b"c", &["UEFI Debug Mode", "DMA Protection Disabled"]);
        let pcr7 = pcr7(&events(&data).unwrap().0);
        assert_eq!(pcr7.actions, ["UEFI Debug Mode", "DMA Protection Disabled"]);
    }

    #[test]
    fn a_log_that_is_not_crypto_agile_or_is_cut_short_is_said_to_be() {
        assert_eq!(events(&[]), None);
        assert_eq!(events(&[0; 64]), None, "no Spec ID header");
        let mut data = shim_boot(b"c", &[]);
        let full = events(&data).unwrap().0.len();
        data.truncate(data.len() - 10);
        let (cut, complete) = events(&data).unwrap();
        assert!(!complete);
        assert_eq!(
            cut.len(),
            full - 1,
            "the event that runs past the end is dropped"
        );
        // An event whose digest uses an algorithm the header did not declare.
        let mut unknown = log(&[(7, EV_SEPARATOR, vec![0; 4])]);
        // From the end: data, size, SHA-256 digest and id, SHA-1 digest, id.
        let at = unknown.len() - 4 - 4 - 32 - 2 - 20 - 2;
        unknown[at..at + 2].copy_from_slice(&0x0012u16.to_le_bytes());
        assert_eq!(events(&unknown), Some((vec![], false)));
    }

    #[test]
    fn variable_data_lengths_are_checked() {
        let mut long = var("db", b"x");
        long[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(variable(&long), None);
        let mut odd = var("db", b"x");
        odd[16..24].copy_from_slice(&(u64::MAX / 2 + 1).to_le_bytes());
        assert_eq!(variable(&odd), None, "a name length that overflows");
        assert_eq!(variable(&[0; 10]), None);
    }
}
