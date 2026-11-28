// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::ip3y::{validate, IrError, Layout, Plane};

const FORMAT: Layout = Layout {
    queue: 9,
    fourcc: 0x7933_7069,
    planes: 1,
    field: 1,
    width: 640,
    height: 480,
    stride: 832,
    size_image: 399_360,
};

const PLANE: Plane = Plane {
    flags: 0,
    length: 399_500,
    offset: 8,
    bytes_used: 399_368,
};

#[test]
fn reference_layout_decodes_without_padding() {
    let mut data = vec![0; 400_000];
    data[..8].fill(0xff);
    data[8..13].copy_from_slice(&[0x01, 0x08, 0x00, 0xe0, 0xff]);
    data[8 + 832] = 7;
    data[8 + 817..8 + 819].copy_from_slice(&[0xf0, 0xc0]);
    let image = validate(FORMAT, PLANE, &data).expect("complete non-face payload");
    assert_eq!(
        (0..4).map(|i| image.sample(0, i)).collect::<Vec<_>>(),
        vec![Some(1), Some(2), Some(512), Some(1023)]
    );
    assert_eq!(
        (image.sample(1, 0), image.sample(0, 639)),
        (Some(7), Some(15))
    );
    assert_eq!((image.sample(0, 640), image.sample(480, 0)), (None, None));
    assert_eq!(
        (image.sample(usize::MAX, 0), image.sample(0, usize::MAX)),
        (None, None)
    );
}

#[test]
fn exact_layout_and_error_flag_refuse() {
    let bytes = vec![0; 400_000];
    for layout in [
        Layout { queue: 1, ..FORMAT },
        Layout {
            fourcc: 0,
            ..FORMAT
        },
        Layout {
            planes: 0,
            ..FORMAT
        },
        Layout {
            planes: 2,
            ..FORMAT
        },
        Layout { field: 0, ..FORMAT },
        Layout {
            width: 639,
            ..FORMAT
        },
        Layout {
            height: 481,
            ..FORMAT
        },
        Layout {
            stride: 833,
            ..FORMAT
        },
        Layout {
            size_image: 399_361,
            ..FORMAT
        },
    ] {
        assert_eq!(
            validate(layout, PLANE, &bytes).unwrap_err(),
            IrError::Format,
            "{layout:?}"
        );
    }
    let flagged = Plane {
        flags: 0x40,
        ..PLANE
    };
    assert_eq!(
        validate(FORMAT, flagged, &bytes).unwrap_err(),
        IrError::Completion
    );
}

#[test]
fn extent_is_checked_before_slicing() {
    let bytes = vec![0; 400_000];
    for plane in [
        Plane {
            offset: 399_369,
            ..PLANE
        },
        Plane {
            offset: usize::MAX,
            ..PLANE
        },
        Plane {
            length: 400_001,
            ..PLANE
        },
        Plane {
            length: 399_367,
            ..PLANE
        },
        Plane {
            bytes_used: 399_367,
            ..PLANE
        },
        Plane {
            bytes_used: 399_369,
            ..PLANE
        },
    ] {
        assert_eq!(
            validate(FORMAT, plane, &bytes).unwrap_err(),
            IrError::Extent
        );
    }
}
