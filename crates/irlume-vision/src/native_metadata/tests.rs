// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use super::{inspect, MetadataError, Notice, StringKind};

const BASE: u64 = 0x1000;
const DYNAMIC: usize = 0x400;
const INTERP: usize = 0x300;

fn u16_at(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn u32_at(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn u64_at(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn phdr(bytes: &mut [u8], index: usize, kind: u32, offset: u64, address: u64, size: u64) {
    let at = 64 + index * 56;
    u32_at(bytes, at, kind);
    u32_at(bytes, at + 4, 4);
    u64_at(bytes, at + 8, offset);
    u64_at(bytes, at + 16, address);
    u64_at(bytes, at + 32, size);
    u64_at(bytes, at + 40, size);
    u64_at(bytes, at + 48, 1);
}

fn fixture(entries: &[(i64, u64)], strings: &[u8], interpreter: Option<&[u8]>) -> Vec<u8> {
    let strings_at = DYNAMIC + entries.len() * 16 + 32;
    let mut bytes = vec![0; strings_at + strings.len() + 32];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    u16_at(&mut bytes, 16, 3);
    u16_at(&mut bytes, 18, 62);
    u32_at(&mut bytes, 20, 1);
    u64_at(&mut bytes, 32, 64);
    u16_at(&mut bytes, 52, 64);
    u16_at(&mut bytes, 54, 56);
    u16_at(&mut bytes, 56, if interpreter.is_some() { 3 } else { 2 });
    let length = bytes.len() as u64;
    phdr(&mut bytes, 0, 1, 0, BASE, length);
    phdr(
        &mut bytes,
        1,
        2,
        DYNAMIC as u64,
        BASE + DYNAMIC as u64,
        (entries.len() * 16) as u64,
    );
    if let Some(interpreter) = interpreter {
        bytes[INTERP..INTERP + interpreter.len()].copy_from_slice(interpreter);
        phdr(
            &mut bytes,
            2,
            3,
            INTERP as u64,
            BASE + INTERP as u64,
            interpreter.len() as u64,
        );
    }
    for (index, &(tag, value)) in entries.iter().enumerate() {
        u64_at(&mut bytes, DYNAMIC + index * 16, tag as u64);
        u64_at(
            &mut bytes,
            DYNAMIC + index * 16 + 8,
            if tag == 5 {
                BASE + strings_at as u64
            } else {
                value
            },
        );
    }
    bytes[strings_at..strings_at + strings.len()].copy_from_slice(strings);
    bytes
}

fn sample() -> Vec<u8> {
    fixture(
        &[
            (5, 0),
            (10, 34),
            (1, 1),
            (14, 9),
            (15, 17),
            (29, 25),
            (0, 0),
        ],
        b"\0liba.so\0self.so\0$ORIGIN\0raw:path\0",
        Some(b"/loader\0"),
    )
}

fn assert_error(bytes: &[u8], expected: MetadataError) {
    assert!(matches!(inspect(bytes), Err(error) if error == expected));
}

#[test]
fn extracts_program_header_metadata_without_sections() {
    let bytes = sample();
    let metadata = inspect(&bytes).unwrap();
    assert_eq!(metadata.header().machine, 62);
    assert_eq!(metadata.header().file_type, 3);
    assert_eq!(metadata.program_headers().len(), 3);
    assert_eq!(metadata.interpreter(), Some(b"/loader".as_slice()));
    let strings: Vec<_> = metadata
        .strings()
        .iter()
        .map(|s| (s.kind(), s.bytes()))
        .collect();
    assert_eq!(
        strings,
        vec![
            (StringKind::Needed, b"liba.so".as_slice()),
            (StringKind::Soname, b"self.so"),
            (StringKind::Rpath, b"$ORIGIN"),
            (StringKind::Runpath, b"raw:path")
        ]
    );
    assert_eq!(metadata.terminator_index(), Some(6));
    assert_eq!(metadata.active_dynamic_entries().len(), 6);
    assert!(metadata.trailing_dynamic_entries().is_empty());
}

#[test]
fn ignores_conflicting_section_dynamic_metadata() {
    let mut bytes = sample();
    // Section-table fields are deliberately impossible. Only the valid program
    // headers may supply the dynamic metadata.
    u64_at(&mut bytes, 40, u64::MAX);
    u16_at(&mut bytes, 58, 64);
    u16_at(&mut bytes, 60, 10);
    assert_eq!(inspect(&bytes).unwrap().strings()[0].bytes(), b"liba.so");
}

#[test]
fn preserves_raw_strings_unknown_tags_and_loading_notices() {
    let bytes = fixture(
        &[
            (5, 0),
            (10, 5),
            (1, 1),
            (15, 3),
            (0x123456, 99),
            (0x7fffffff, 1),
            (0, 0),
        ],
        b"\0\xff\0\0\0",
        None,
    );
    let metadata = inspect(&bytes).unwrap();
    assert_eq!(metadata.strings()[0].bytes(), b"\xff");
    assert_eq!(metadata.strings()[1].bytes(), b"");
    assert!(metadata.notices().contains(&Notice::UnknownDynamicTag {
        index: 4,
        tag: 0x123456
    }));
    assert!(metadata
        .notices()
        .contains(&Notice::UninterpretedDynamicTag {
            index: 5,
            tag: 0x7fffffff
        }));
    assert!(metadata
        .notices()
        .contains(&Notice::UninterpretedDynamicTag { index: 3, tag: 15 }));
}

#[test]
fn preserves_needed_order_duplicates_and_empty_values() {
    let bytes = fixture(
        &[
            (5, 0),
            (10, 5),
            (1, 1),
            (1, 0),
            (1, 1),
            (14, 1),
            (14, 0),
            (0, 0),
        ],
        b"\0abc\0",
        None,
    );
    let metadata = inspect(&bytes).unwrap();
    assert_eq!(
        metadata
            .strings()
            .iter()
            .map(|s| s.bytes())
            .collect::<Vec<_>>(),
        vec![b"abc".as_slice(), b"", b"abc", b"abc", b""]
    );
    assert!(metadata
        .notices()
        .contains(&Notice::RepeatedStringTag { index: 4, tag: 1 }));
    assert!(metadata
        .notices()
        .contains(&Notice::RepeatedStringTag { index: 6, tag: 14 }));
}

#[test]
fn distinguishes_dynamic_terminator_and_trailing_entries() {
    let bytes = fixture(
        &[
            (0, 0),
            (1, u64::MAX),
            (5, u64::MAX),
            (10, u64::MAX),
            (15, u64::MAX),
            (0x123456, 7),
        ],
        b"",
        None,
    );
    let metadata = inspect(&bytes).unwrap();
    assert_eq!(metadata.terminator_index(), Some(0));
    assert_eq!(metadata.dynamic_entries().len(), 6);
    assert_eq!(metadata.trailing_dynamic_entries().len(), 5);
    assert_eq!(metadata.dynamic_bytes().unwrap().len(), 96);
    assert!(metadata.strings().is_empty());
    assert!(metadata.notices().contains(&Notice::TrailingDynamicEntries));
}

#[test]
fn rejects_truncation_overflow_and_ambiguous_translation() {
    let bytes = sample();
    for end in 0..64 {
        assert!(inspect(&bytes[..end]).is_err());
    }
    let mut bad = sample();
    u64_at(&mut bad, 32, u64::MAX);
    assert_error(&bad, MetadataError::Range);
    let mut bad = sample();
    u64_at(&mut bad, 64 + 8, u64::MAX);
    assert_error(&bad, MetadataError::Range);
    let mut bad = sample();
    u16_at(&mut bad, 56, 4);
    let size = bad.len() as u64;
    phdr(&mut bad, 3, 1, 0, BASE, size);
    assert_error(&bad, MetadataError::StringTableMapping);
    let mut bad = sample();
    u64_at(&mut bad, 64 + 32, 64);
    assert_error(&bad, MetadataError::StringTableMapping);
}

#[test]
fn rejects_duplicate_singletons_and_unterminated_strings() {
    for entries in [
        vec![(5, 0), (5, 0), (10, 2), (1, 0), (0, 0)],
        vec![(5, 0), (10, 2), (10, 2), (1, 0), (0, 0)],
    ] {
        assert_error(
            &fixture(&entries, b"x\0", None),
            MetadataError::DuplicateStringTable,
        );
    }
    assert_error(
        &fixture(&[(1, 0), (0, 0)], b"", None),
        MetadataError::MissingStringTable,
    );
    assert_error(
        &fixture(&[(5, 0), (10, 1), (1, 0), (0, 0)], b"x", None),
        MetadataError::UnterminatedString,
    );
    assert_error(
        &fixture(&[(0, 0)], b"", Some(b"/no-nul")),
        MetadataError::UnterminatedString,
    );
    assert_error(
        &fixture(&[(1, 0)], b"", None),
        MetadataError::DynamicTerminator,
    );
    let mut bad = sample();
    u16_at(&mut bad, 56, 4);
    phdr(&mut bad, 3, 2, DYNAMIC as u64, BASE, 16);
    assert_error(&bad, MetadataError::DuplicateSegment);
}

#[test]
fn enforces_exact_metadata_resource_bounds() {
    assert_eq!(super::MAX_INPUT_BYTES, 256 * 1024 * 1024);
    let mut bytes = fixture(&vec![(0, 0); super::MAX_DYNAMIC_ENTRIES], b"", None);
    assert_eq!(
        inspect(&bytes).unwrap().dynamic_entries().len(),
        super::MAX_DYNAMIC_ENTRIES
    );
    u64_at(
        &mut bytes,
        64 + 56 + 32,
        ((super::MAX_DYNAMIC_ENTRIES + 1) * 16) as u64,
    );
    assert_error(&bytes, MetadataError::Bounds);
    let mut bad = sample();
    u16_at(&mut bad, 56, 129);
    assert_error(&bad, MetadataError::Bounds);
    let mut strings = vec![b'x'; super::MAX_STRING_BYTES];
    strings.push(0);
    let mut entries = vec![(5, 0), (10, strings.len() as u64)];
    entries.extend(vec![(1, 0); super::MAX_STRING_REFERENCES]);
    entries.push((0, 0));
    assert_eq!(
        inspect(&fixture(&entries, &strings, None))
            .unwrap()
            .strings()
            .len(),
        super::MAX_STRING_REFERENCES
    );
    entries.insert(2, (1, 0));
    assert_error(&fixture(&entries, &strings, None), MetadataError::Bounds);
    strings.insert(0, b'x');
    assert_error(
        &fixture(
            &[(5, 0), (10, strings.len() as u64), (1, 0), (0, 0)],
            &strings,
            None,
        ),
        MetadataError::Bounds,
    );
}

#[test]
fn borrows_the_supplied_buffer_without_ambient_access() {
    let bytes = sample();
    let metadata = inspect(&bytes).unwrap();
    let base = bytes.as_ptr() as usize;
    for string in metadata.strings() {
        let start = string.bytes().as_ptr() as usize;
        assert!(start >= base && start + string.bytes().len() <= base + bytes.len());
    }
    let source = include_str!("../native_metadata.rs");
    for forbidden in [
        "std::fs",
        "std::env",
        "std::process",
        "libloading",
        "openvino::",
        "ElfBytes::",
        "unsafe {",
    ] {
        assert!(
            !source.contains(forbidden),
            "unexpected dependency: {forbidden}"
        );
    }
}

#[test]
fn metadata_success_does_not_authorize_loading() {
    let bytes = sample();
    let metadata = inspect(&bytes).unwrap();
    assert!(metadata
        .notices()
        .iter()
        .any(|n| matches!(n, Notice::UninterpretedDynamicTag { .. })));
    #[cfg(feature = "npu")]
    assert!(matches!(
        crate::npu::gpu::discover(&crate::npu::RuntimeSelection::Automatic),
        crate::npu::gpu::Discovery::NotAdmitted
    ));
    // This ordinary feature does not add an evidence opt-in. An independently
    // selected evidence cfg retains the existing propagation contract.
    assert_eq!(
        std::hint::black_box(crate::HARDWARE_EVIDENCE_BUILD),
        cfg!(irlume_hw_evidence) || irlume_common::HARDWARE_EVIDENCE_BUILD,
    );
}

#[test]
fn unknown_program_headers_and_header_flags_are_reported() {
    let mut bytes = sample();
    u32_at(&mut bytes, 48, 1);
    u16_at(&mut bytes, 56, 4);
    phdr(&mut bytes, 3, 0x1234, 0, 0, 0);
    let metadata = inspect(&bytes).unwrap();
    assert_eq!(metadata.header().flags, 1);
    assert!(metadata.notices().contains(&Notice::HeaderFlags));
    assert!(metadata.notices().contains(&Notice::UnknownProgramHeader {
        index: 3,
        kind: 0x1234
    }));
}

#[test]
fn format_and_entry_sizes_fail_explicitly() {
    for (at, value) in [(4, 1), (5, 2), (7, 255)] {
        let mut bad = sample();
        bad[at] = value;
        assert_error(&bad, MetadataError::UnsupportedFormat);
    }
    for (at, value) in [(52, 63), (54, 55), (56, 0xffff)] {
        let mut bad = sample();
        u16_at(&mut bad, at, value);
        assert_error(&bad, MetadataError::HeaderLayout);
    }
    let mut bad = sample();
    u16_at(&mut bad, 18, 183);
    assert_error(&bad, MetadataError::UnsupportedFormat);
    let mut bad = sample();
    u32_at(&mut bad, 20, 2);
    assert_error(&bad, MetadataError::UnsupportedFormat);
}

#[test]
fn exact_input_and_program_header_bounds_are_accepted() {
    let mut bytes = vec![0; super::MAX_INPUT_BYTES + 1];
    bytes[..64].copy_from_slice(&sample()[..64]);
    u16_at(&mut bytes, 56, 0);
    u64_at(&mut bytes, 32, 0);
    assert!(inspect(&bytes[..super::MAX_INPUT_BYTES]).is_ok());
    assert_error(&bytes, MetadataError::Bounds);
    drop(bytes);

    let mut bytes = vec![0; 64 + super::MAX_PROGRAM_HEADERS * 56];
    bytes[..64].copy_from_slice(&sample()[..64]);
    u16_at(&mut bytes, 56, super::MAX_PROGRAM_HEADERS as u16);
    assert_eq!(
        inspect(&bytes).unwrap().program_headers().len(),
        super::MAX_PROGRAM_HEADERS,
    );
}

#[test]
fn absent_dynamic_and_interpreter_are_distinct_from_empty_strings() {
    let mut bytes = sample();
    u16_at(&mut bytes, 56, 0);
    u64_at(&mut bytes, 32, 0);
    let metadata = inspect(&bytes).unwrap();
    assert_eq!(metadata.interpreter(), None);
    assert_eq!(metadata.dynamic_bytes(), None);
    assert_eq!(metadata.terminator_index(), None);
    assert!(metadata.active_dynamic_entries().is_empty());
    assert!(metadata.trailing_dynamic_entries().is_empty());

    let bytes = fixture(&[(0, 0)], b"", Some(b"\0"));
    assert_eq!(inspect(&bytes).unwrap().interpreter(), Some(b"".as_slice()));
}

#[test]
fn incomplete_dynamic_entries_and_load_overflows_are_refused() {
    let mut bytes = sample();
    u64_at(&mut bytes, 64 + 56 + 32, 17);
    assert_error(&bytes, MetadataError::Range);

    let mut bytes = sample();
    u64_at(&mut bytes, 64 + 40, 0);
    assert_error(&bytes, MetadataError::Range);

    let mut bytes = sample();
    u64_at(&mut bytes, 64 + 16, u64::MAX);
    assert_error(&bytes, MetadataError::Range);

    let mut bytes = sample();
    u64_at(&mut bytes, DYNAMIC + 8, u64::MAX);
    assert_error(&bytes, MetadataError::Range);
}

#[test]
fn repeated_search_paths_and_post_terminator_singletons_stay_raw() {
    let bytes = fixture(
        &[
            (5, 0),
            (10, 2),
            (15, 0),
            (15, 1),
            (29, 0),
            (29, 1),
            (0, 0),
            (5, 1),
            (5, 2),
        ],
        b"\0\0",
        None,
    );
    let metadata = inspect(&bytes).unwrap();
    assert_eq!(metadata.strings().len(), 4);
    assert!(metadata
        .strings()
        .iter()
        .all(|string| string.bytes().is_empty()));
    assert_eq!(metadata.strings()[0].entry_index(), 2);
    assert_eq!(metadata.trailing_dynamic_entries().len(), 2);
    assert!(metadata
        .notices()
        .contains(&Notice::RepeatedStringTag { index: 3, tag: 15 }));
    assert!(metadata
        .notices()
        .contains(&Notice::RepeatedStringTag { index: 5, tag: 29 }));
}

#[test]
fn interpreter_counts_against_string_budget_and_stays_unresolved() {
    let mut entries = vec![(5, 0), (10, 1)];
    entries.extend(vec![(1, 0); super::MAX_STRING_REFERENCES - 1]);
    entries.push((0, 0));
    let bytes = fixture(&entries, b"\0", Some(b"relative/\xff\0"));
    assert_eq!(
        inspect(&bytes).unwrap().interpreter(),
        Some(b"relative/\xff".as_slice())
    );
    entries.insert(2, (1, 0));
    assert_error(
        &fixture(&entries, b"\0", Some(b"loader\0")),
        MetadataError::Bounds,
    );
}

#[test]
fn string_table_size_and_offsets_cannot_escape_file_backed_data() {
    let mut bytes = sample();
    u64_at(&mut bytes, DYNAMIC + 16 + 8, u64::MAX);
    assert_error(&bytes, MetadataError::Range);
    let mut bytes = sample();
    u64_at(&mut bytes, DYNAMIC + 2 * 16 + 8, u64::MAX);
    assert_error(&bytes, MetadataError::Range);
    let bytes = fixture(&[(10, 1), (0, 0)], b"\0", None);
    assert_error(&bytes, MetadataError::MissingStringTable);
}

#[test]
fn rejects_partial_string_table_load_overlaps() {
    // sample()'s STRTAB is at file offset 0x490, virtual 0x1490..0x14b2.
    let table_start = BASE + 0x490;
    let table_end = table_start + 34;
    for (address, file_offset, file_size, memory_size) in [
        (table_start - 4, 0x300, 8, 8),  // prefix
        (table_start + 1, 0x300, 8, 8),  // interior: the reported reproduction
        (table_end - 4, 0x300, 8, 8),    // suffix
        (table_start + 1, 0x491, 8, 8),  // identical bytes still mean two mappings
        (table_start - 4, 0x300, 0, 8),  // zero-fill prefix
        (table_start + 1, 0x300, 0, 8),  // zero-fill interior
        (table_end - 4, 0x300, 0, 8),    // zero-fill suffix
        (table_start - 8, 0x300, 4, 16), // only the zero-fill tail intersects
    ] {
        let mut bytes = sample();
        u16_at(&mut bytes, 56, 4);
        phdr(&mut bytes, 3, 1, file_offset, address, file_size);
        u64_at(&mut bytes, 64 + 3 * 56 + 40, memory_size);
        assert_error(&bytes, MetadataError::StringTableMapping);

        // A partial competitor must also refuse when listed before the full
        // mapping, rather than depending on which segment the parser sees first.
        let first = bytes[64..120].to_vec();
        let other = bytes[64 + 3 * 56..64 + 4 * 56].to_vec();
        bytes[64..120].copy_from_slice(&other);
        bytes[64 + 3 * 56..64 + 4 * 56].copy_from_slice(&first);
        assert_error(&bytes, MetadataError::StringTableMapping);
    }

    for (address, file_size, memory_size) in [
        (table_start - 8, 8, 8), // touching the prefix is not an intersection
        (table_end, 8, 8),       // touching the suffix is not an intersection
        (table_start + 1, 0, 0), // an empty memory range maps no competing bytes
    ] {
        let mut bytes = sample();
        u16_at(&mut bytes, 56, 4);
        phdr(&mut bytes, 3, 1, 0x300, address, file_size);
        u64_at(&mut bytes, 64 + 3 * 56 + 40, memory_size);
        assert_eq!(inspect(&bytes).unwrap().strings()[0].bytes(), b"liba.so");
    }
}
