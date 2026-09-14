// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! No-rewrite guard for SHA-verified TFLite artifacts.
//!
//! This is a bounded inspection of Model.buffers and Buffer.offset, not a model
//! validator. The audited upstream loader rewrites exactly when a buffer has a
//! nonzero offset. Reject that representation before calling it. Full schema
//! and graph validation remain with the upstream loader and TFLite runtime.
//! Field slots are from the TFLite schema audited with edgefirst-tflite 0.10.1.

const MALFORMED: &str = "invalid TFLite model-buffer layout";
const OFFSET_STORED: &str =
    "offset-stored TFLite buffers are unsupported; approved models must load unchanged";
const MODEL_BUFFERS_SLOT: usize = 12;
const BUFFER_OFFSET_SLOT: usize = 6;

fn bytes_at<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N], &'static str> {
    bytes
        .get(at..at.checked_add(N).ok_or(MALFORMED)?)
        .and_then(|value| value.try_into().ok())
        .ok_or(MALFORMED)
}

fn reference(bytes: &[u8], at: usize) -> Result<usize, &'static str> {
    let relative =
        usize::try_from(u32::from_le_bytes(bytes_at(bytes, at)?)).map_err(|_| MALFORMED)?;
    if relative == 0 {
        return Err(MALFORMED);
    }
    at.checked_add(relative).ok_or(MALFORMED)
}

fn field(
    bytes: &[u8],
    table: usize,
    slot: usize,
    width: usize,
) -> Result<Option<usize>, &'static str> {
    let displacement = i32::from_le_bytes(bytes_at(bytes, table)?);
    let distance = usize::try_from(displacement.unsigned_abs()).map_err(|_| MALFORMED)?;
    // Deduplicated vtables may appear after their table, so the displacement
    // is signed. Checked arithmetic also handles i32::MIN without negation.
    let vtable = if displacement >= 0 {
        table.checked_sub(distance)
    } else {
        table.checked_add(distance)
    }
    .ok_or(MALFORMED)?;
    let vtable_len = usize::from(u16::from_le_bytes(bytes_at(bytes, vtable)?));
    let object_len = usize::from(u16::from_le_bytes(bytes_at(
        bytes,
        vtable.checked_add(2).ok_or(MALFORMED)?,
    )?));
    if vtable_len < 4 || vtable_len % 2 != 0 || object_len < 4 {
        return Err(MALFORMED);
    }
    bytes
        .get(vtable..vtable.checked_add(vtable_len).ok_or(MALFORMED)?)
        .ok_or(MALFORMED)?;
    bytes
        .get(table..table.checked_add(object_len).ok_or(MALFORMED)?)
        .ok_or(MALFORMED)?;
    if slot >= vtable_len {
        return Ok(None);
    }
    let offset = usize::from(u16::from_le_bytes(bytes_at(
        bytes,
        vtable.checked_add(slot).ok_or(MALFORMED)?,
    )?));
    if offset == 0 {
        return Ok(None);
    }
    if offset < 4 || offset.checked_add(width).ok_or(MALFORMED)? > object_len {
        return Err(MALFORMED);
    }
    Ok(Some(table.checked_add(offset).ok_or(MALFORMED)?))
}

/// Inspect already hash-verified bytes without allocation, unsafe reads or I/O.
pub(super) fn require_inline_buffers(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.get(4..8) != Some(b"TFL3") {
        return Err(MALFORMED);
    }
    let model = reference(bytes, 0)?;
    let Some(buffers) = field(bytes, model, MODEL_BUFFERS_SLOT, 4)? else {
        return Ok(());
    };
    let vector = reference(bytes, buffers)?;
    let count =
        usize::try_from(u32::from_le_bytes(bytes_at(bytes, vector)?)).map_err(|_| MALFORMED)?;
    let start = vector.checked_add(4).ok_or(MALFORMED)?;
    let size = count.checked_mul(4).ok_or(MALFORMED)?;
    bytes
        .get(start..start.checked_add(size).ok_or(MALFORMED)?)
        .ok_or(MALFORMED)?;
    for index in 0..count {
        let entry = start
            .checked_add(index.checked_mul(4).ok_or(MALFORMED)?)
            .ok_or(MALFORMED)?;
        let buffer = reference(bytes, entry)?;
        if let Some(offset) = field(bytes, buffer, BUFFER_OFFSET_SLOT, 8)? {
            if u64::from_le_bytes(bytes_at(bytes, offset)?) != 0 {
                return Err(OFFSET_STORED);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    // Synthetic tables only, no model weights, images or biometric data.
    pub(crate) fn fixture(offset: u64) -> Vec<u8> {
        let mut bytes = vec![0; 128];
        bytes[0..4].copy_from_slice(&64_u32.to_le_bytes());
        bytes[4..8].copy_from_slice(b"TFL3");
        bytes[8..10].copy_from_slice(&14_u16.to_le_bytes());
        bytes[10..12].copy_from_slice(&12_u16.to_le_bytes());
        bytes[12..14].copy_from_slice(&4_u16.to_le_bytes());
        bytes[20..22].copy_from_slice(&8_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&56_i32.to_le_bytes());
        bytes[68..72].copy_from_slice(&3_u32.to_le_bytes());
        bytes[72..76].copy_from_slice(&12_u32.to_le_bytes());
        bytes[84..88].copy_from_slice(&1_u32.to_le_bytes());
        bytes[88..92].copy_from_slice(&16_u32.to_le_bytes());
        bytes[32..34].copy_from_slice(&10_u16.to_le_bytes());
        bytes[34..36].copy_from_slice(&24_u16.to_le_bytes());
        bytes[38..40].copy_from_slice(&8_u16.to_le_bytes());
        bytes[40..42].copy_from_slice(&16_u16.to_le_bytes());
        bytes[104..108].copy_from_slice(&72_i32.to_le_bytes());
        bytes[112..120].copy_from_slice(&offset.to_le_bytes());
        bytes[120..128].copy_from_slice(&4_u64.to_le_bytes());
        bytes
    }

    #[test]
    fn inline_and_absent_default_offsets_are_accepted() {
        let mut bytes = fixture(0);
        assert_eq!(require_inline_buffers(&bytes), Ok(()));
        bytes[38..40].fill(0); // omitted Buffer.offset has the schema default 0
        assert_eq!(require_inline_buffers(&bytes), Ok(()));
        bytes[20..22].fill(0); // omitted Model.buffers cannot cause rewriting
        assert_eq!(require_inline_buffers(&bytes), Ok(()));
    }

    #[test]
    fn every_nonzero_offset_is_rejected() {
        for offset in [1, 128, u64::MAX] {
            assert_eq!(require_inline_buffers(&fixture(offset)), Err(OFFSET_STORED));
        }
    }

    #[test]
    fn every_buffer_is_checked_and_an_empty_vector_is_allowed() {
        let mut bytes = fixture(0);
        bytes[84..88].fill(0);
        assert_eq!(require_inline_buffers(&bytes), Ok(()));
        bytes.resize(184, 0);
        bytes[84..88].copy_from_slice(&2_u32.to_le_bytes());
        bytes[92..96].copy_from_slice(&68_u32.to_le_bytes());
        bytes[160..164].copy_from_slice(&128_i32.to_le_bytes());
        bytes[168..176].copy_from_slice(&184_u64.to_le_bytes());
        assert_eq!(require_inline_buffers(&bytes), Err(OFFSET_STORED));
    }

    #[test]
    fn signed_vtable_displacement_is_supported() {
        let mut bytes = fixture(0);
        let vtable = bytes[32..42].to_vec();
        bytes.resize(146, 0);
        bytes[136..146].copy_from_slice(&vtable);
        bytes[104..108].copy_from_slice(&(-32_i32).to_le_bytes());
        assert_eq!(require_inline_buffers(&bytes), Ok(()));
        bytes[112..120].copy_from_slice(&1_u64.to_le_bytes());
        assert_eq!(require_inline_buffers(&bytes), Err(OFFSET_STORED));
    }

    #[test]
    fn truncated_and_malformed_layouts_are_rejected_without_panics() {
        let bytes = fixture(0);
        for end in 0..bytes.len() {
            assert_eq!(require_inline_buffers(&bytes[..end]), Err(MALFORMED));
        }
        for (at, replacement) in [
            (0, u32::MAX.to_le_bytes()),
            (64, i32::MIN.to_le_bytes()),
            (72, u32::MAX.to_le_bytes()),
            (84, u32::MAX.to_le_bytes()),
            (88, 0_u32.to_le_bytes()),
        ] {
            let mut invalid = bytes.clone();
            invalid[at..at + 4].copy_from_slice(&replacement);
            assert_eq!(require_inline_buffers(&invalid), Err(MALFORMED));
        }
        let mut invalid = bytes;
        invalid[38..40].copy_from_slice(&22_u16.to_le_bytes());
        assert_eq!(require_inline_buffers(&invalid), Err(MALFORMED));
    }
}
