// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Layout {
    pub queue: u32,
    pub fourcc: u32,
    pub planes: u8,
    pub field: u32,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub size_image: u32,
}

#[derive(Clone, Copy)]
pub(super) struct Plane {
    pub flags: u32,
    pub length: usize,
    pub offset: usize,
    pub bytes_used: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum IrError {
    Format,
    Completion,
    Extent,
}

#[derive(Debug)]
pub(super) struct Ip3y<'a>(&'a [u8]);

const REFERENCE: Layout = Layout {
    queue: 9,
    fourcc: u32::from_le_bytes(*b"ip3y"),
    planes: 1,
    field: 1,
    width: 640,
    height: 480,
    stride: 832,
    size_image: 399_360,
};

pub(super) fn validate(layout: Layout, plane: Plane, mapped: &[u8]) -> Result<Ip3y<'_>, IrError> {
    if layout != REFERENCE {
        return Err(IrError::Format);
    }
    if plane.flags & 0x40 != 0 {
        return Err(IrError::Completion);
    }
    if plane.length > mapped.len()
        || plane.bytes_used > plane.length
        || plane.bytes_used.checked_sub(plane.offset) != Some(399_360)
    {
        return Err(IrError::Extent);
    }
    Ok(Ip3y(&mapped[plane.offset..plane.bytes_used]))
}

impl Ip3y<'_> {
    pub(super) fn sample(&self, row: usize, column: usize) -> Option<u16> {
        if row >= 480 || column >= 640 {
            return None;
        }
        let bit = (column % 25) * 10;
        let byte = row * 832 + (column / 25) * 32 + bit / 8;
        let window = u16::from_le_bytes([self.0[byte], self.0[byte + 1]]);
        Some((window >> (bit % 8)) & 0x03ff)
    }
}
