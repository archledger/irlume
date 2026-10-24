#![no_main]
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! Bounded metadata extraction from supplied ELF bytes, without native loading.

use irlume_vision::native_metadata::{self, ElfMetadata};
use libfuzzer_sys::fuzz_target;

fn check_bounds(data: &[u8], metadata: &ElfMetadata<'_>) {
    assert!(metadata.program_headers().len() <= native_metadata::MAX_PROGRAM_HEADERS);
    assert!(metadata.dynamic_entries().len() <= native_metadata::MAX_DYNAMIC_ENTRIES);
    let mut count = 0usize;
    let mut total = 0usize;
    let start = data.as_ptr() as usize;
    let end = start.checked_add(data.len()).unwrap();
    for bytes in metadata
        .interpreter()
        .into_iter()
        .chain(metadata.strings().iter().map(|s| s.bytes()))
    {
        count += 1;
        total = total.checked_add(bytes.len()).unwrap();
        assert!(bytes.len() <= native_metadata::MAX_STRING_BYTES);
        let address = bytes.as_ptr() as usize;
        assert!(address >= start && address.checked_add(bytes.len()).unwrap() <= end);
    }
    assert!(count <= native_metadata::MAX_STRING_REFERENCES);
    assert!(total <= native_metadata::MAX_REFERENCED_STRING_BYTES);
}

fuzz_target!(|data: &[u8]| {
    match (
        native_metadata::inspect(data),
        native_metadata::inspect(data),
    ) {
        (Err(a), Err(b)) => assert!(a == b),
        (Ok(a), Ok(b)) => {
            check_bounds(data, &a);
            check_bounds(data, &b);
            assert!(a.header() == b.header());
            assert!(a.program_headers() == b.program_headers());
            assert!(a.interpreter() == b.interpreter());
            assert!(a.dynamic_bytes() == b.dynamic_bytes());
            assert!(a.dynamic_entries() == b.dynamic_entries());
            assert!(a.terminator_index() == b.terminator_index());
            assert!(a.notices() == b.notices());
            assert!(a.strings().len() == b.strings().len());
            for (left, right) in a.strings().iter().zip(b.strings()) {
                assert!(left.kind() == right.kind());
                assert!(left.entry_index() == right.entry_index());
                assert!(left.bytes() == right.bytes());
            }
        }
        _ => panic!("metadata parsing is not deterministic"),
    }
});
