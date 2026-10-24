// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Bounded supplied-byte ELF metadata, never a loader or admission capability.
//! Neither paths nor process state are observed. Extracted strings remain
//! borrowed from the caller's buffer; no dependency resolution is performed.

use elf::endian::LittleEndian;
use elf::file::{parse_ident, Class, FileHeader};
use elf::parse::ParseAt;

/// Largest accepted supplied file, in bytes.
pub const MAX_INPUT_BYTES: usize = 256 * 1024 * 1024;
/// Largest accepted program-header count.
pub const MAX_PROGRAM_HEADERS: usize = 128;
/// Largest accepted dynamic-entry count, including terminator and trailing data.
pub const MAX_DYNAMIC_ENTRIES: usize = 4096;
/// Largest number of string references, including the interpreter and duplicates.
pub const MAX_STRING_REFERENCES: usize = 256;
/// Largest accepted string body, not including its terminating NUL.
pub const MAX_STRING_BYTES: usize = 4096;
/// Largest sum of extracted string body lengths, including duplicate references.
pub const MAX_REFERENCED_STRING_BYTES: usize = 1024 * 1024;

/// A structural refusal. No variant retains caller bytes or parser error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataError {
    /// A fixed resource limit was exceeded.
    Bounds,
    /// The ELF identification or file header is malformed or truncated.
    Header,
    /// The well-formed identification names an unsupported format.
    UnsupportedFormat,
    /// An entry size or extended program-header count is unsupported.
    HeaderLayout,
    /// A range overflows, is truncated, or is inconsistent with file-backed data.
    Range,
    /// Multiple interpreter or dynamic segments were supplied.
    DuplicateSegment,
    /// A dynamic segment has no complete terminating entry.
    DynamicTerminator,
    /// An active string-table address or size was supplied twice.
    DuplicateStringTable,
    /// An active string reference lacks the required string table.
    MissingStringTable,
    /// No unique file-backed segment covers the string table.
    StringTableMapping,
    /// A string has no NUL inside its bounded available range.
    UnterminatedString,
    /// A bounded metadata allocation could not be reserved.
    Allocation,
}

/// Raw numeric file-header fields, not a claim that the file can execute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// ELF class (2 for this parser's supported format).
    pub class: u8,
    /// Byte order (1 for little endian).
    pub byte_order: u8,
    /// ELF version.
    pub version: u32,
    /// OS ABI identification.
    pub os_abi: u8,
    /// OS ABI version, retained without interpretation.
    pub abi_version: u8,
    /// ET_EXEC or ET_DYN.
    pub file_type: u16,
    /// EM_X86_64.
    pub machine: u16,
    /// Processor-specific flags, retained without interpretation.
    pub flags: u32,
}

/// A raw program header. Unknown kinds remain visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramHeader {
    /// Segment kind.
    pub kind: u32,
    /// Segment flags.
    pub flags: u32,
    /// File offset.
    pub offset: u64,
    /// Virtual address.
    pub virtual_address: u64,
    /// Physical address, retained without interpretation.
    pub physical_address: u64,
    /// File-backed byte count.
    pub file_size: u64,
    /// Memory byte count.
    pub memory_size: u64,
    /// Alignment.
    pub alignment: u64,
}

/// An uninterpreted numeric dynamic entry, including trailing entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DynamicEntry {
    /// Signed ELF dynamic tag.
    pub tag: i64,
    /// Raw value or address.
    pub value: u64,
}

/// The active string-valued dynamic tags extracted by this parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StringKind {
    /// DT_NEEDED; order and duplicates are retained.
    Needed,
    /// DT_SONAME, without basename validation.
    Soname,
    /// DT_RPATH, without expansion or splitting.
    Rpath,
    /// DT_RUNPATH, without expansion or splitting.
    Runpath,
}

/// One active string reference. No raw-content Debug or Display implementation.
pub struct DynamicString<'a> {
    kind: StringKind,
    entry_index: usize,
    bytes: &'a [u8],
}

/// Explicit metadata not interpreted as supported loading semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    /// An unknown program-header kind.
    UnknownProgramHeader { index: usize, kind: u32 },
    /// A dynamic tag outside the parser's named metadata set.
    UnknownDynamicTag { index: usize, tag: i64 },
    /// A known but uninterpreted loading tag, including search paths.
    UninterpretedDynamicTag { index: usize, tag: i64 },
    /// An active string-valued tag repeated an earlier one.
    RepeatedStringTag { index: usize, tag: i64 },
    /// Dynamic entries follow the first terminator and are not effective.
    TrailingDynamicEntries,
    /// Header flags are retained but not interpreted.
    HeaderFlags,
}

/// Structurally extracted metadata, not executable support or trusted closure.
/// No raw-content Debug or Display implementation is provided.
///
/// The parser is available in ordinary `native-metadata` builds:
///
/// ```
/// use irlume_vision::native_metadata::{inspect, ElfMetadata, MetadataError};
/// fn describe(bytes: &[u8]) -> Result<ElfMetadata<'_>, MetadataError> {
///     inspect(bytes)
/// }
/// ```
///
/// A successful description has no launch capability:
///
/// ```compile_fail
/// use irlume_vision::native_metadata::ElfMetadata;
/// fn execute(metadata: ElfMetadata<'_>) {
///     metadata.launch();
/// }
/// ```
///
/// Raw metadata is deliberately not printable with Debug:
///
/// ```compile_fail
/// use irlume_vision::native_metadata::ElfMetadata;
/// fn dump(metadata: ElfMetadata<'_>) {
///     let _ = format!("{metadata:?}");
/// }
/// ```
pub struct ElfMetadata<'a> {
    header: Header,
    program_headers: Vec<ProgramHeader>,
    interpreter: Option<&'a [u8]>,
    strings: Vec<DynamicString<'a>>,
    dynamic_bytes: Option<&'a [u8]>,
    dynamic_entries: Vec<DynamicEntry>,
    terminator_index: Option<usize>,
    notices: Vec<Notice>,
}

impl DynamicString<'_> {
    /// The string's declared dynamic-tag role, not validated loading semantics.
    pub fn kind(&self) -> StringKind {
        self.kind
    }

    /// Its index in the complete dynamic-entry array.
    pub fn entry_index(&self) -> usize {
        self.entry_index
    }

    /// The exact string body, excluding its terminating NUL.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }
}

impl ElfMetadata<'_> {
    /// The numeric ELF header observation.
    pub fn header(&self) -> Header {
        self.header
    }

    /// The complete program-header array in file order.
    pub fn program_headers(&self) -> &[ProgramHeader] {
        &self.program_headers
    }

    /// The interpreter bytes without NUL, with no path resolution or validation.
    pub fn interpreter(&self) -> Option<&[u8]> {
        self.interpreter
    }

    /// All effective string references in dynamic-entry order, with duplicates.
    pub fn strings(&self) -> &[DynamicString<'_>] {
        &self.strings
    }

    /// Raw dynamic-segment bytes, including the terminator and trailing data.
    pub fn dynamic_bytes(&self) -> Option<&[u8]> {
        self.dynamic_bytes
    }

    /// Every complete dynamic entry in file order, including trailing entries.
    pub fn dynamic_entries(&self) -> &[DynamicEntry] {
        &self.dynamic_entries
    }

    /// The first DT_NULL index, or None when there is no dynamic segment.
    pub fn terminator_index(&self) -> Option<usize> {
        self.terminator_index
    }

    /// Entries before the first DT_NULL; trailing entries are never effective.
    pub fn active_dynamic_entries(&self) -> &[DynamicEntry] {
        &self.dynamic_entries[..self.terminator_index.unwrap_or(0)]
    }

    /// Entries after the first DT_NULL, retained without resolving their strings.
    pub fn trailing_dynamic_entries(&self) -> &[DynamicEntry] {
        match self.terminator_index {
            Some(index) => &self.dynamic_entries[index + 1..],
            None => &[],
        }
    }

    /// Uninterpreted metadata, with physical array indices also for trailing tags.
    pub fn notices(&self) -> &[Notice] {
        &self.notices
    }
}

fn reserved<T>(count: usize) -> Result<Vec<T>, MetadataError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| MetadataError::Allocation)?;
    Ok(values)
}

fn range(bytes: &[u8], offset: u64, length: u64) -> Result<&[u8], MetadataError> {
    let end = offset.checked_add(length).ok_or(MetadataError::Range)?;
    let start = usize::try_from(offset).map_err(|_| MetadataError::Range)?;
    let end = usize::try_from(end).map_err(|_| MetadataError::Range)?;
    bytes.get(start..end).ok_or(MetadataError::Range)
}

fn string_kind(tag: i64) -> Option<StringKind> {
    match tag {
        1 => Some(StringKind::Needed),
        14 => Some(StringKind::Soname),
        15 => Some(StringKind::Rpath),
        29 => Some(StringKind::Runpath),
        _ => None,
    }
}

fn named_dynamic_tag(tag: i64) -> bool {
    matches!(
        tag,
        0..=30 | 32..=38
            | 0x6ffffdfd // POSFLAG_1
            | 0x6ffffef5 // GNU_HASH
            | 0x6ffffefa..=0x6ffffefc // CONFIG, DEPAUDIT, AUDIT
            | 0x6ffffff0 // VERSYM
            | 0x6ffffff9..=0x6fffffff // Relocation counts, flags, version metadata
            | 0x7ffffffd // AUXILIARY
            | 0x7fffffff // FILTER
    )
}

fn referenced_string<'a>(
    table: &'a [u8],
    offset: u64,
    total: &mut usize,
) -> Result<&'a [u8], MetadataError> {
    let start = usize::try_from(offset).map_err(|_| MetadataError::Range)?;
    let remaining = table.get(start..).ok_or(MetadataError::Range)?;
    let budget = MAX_REFERENCED_STRING_BYTES
        .checked_sub(*total)
        .ok_or(MetadataError::Bounds)?
        .min(MAX_STRING_BYTES);
    // At most budget+1 bytes are inspected, including the possible final NUL.
    // Repeated and overlapping references are charged separately.
    let search = &remaining[..remaining.len().min(budget + 1)];
    let end = match search.iter().position(|byte| *byte == 0) {
        Some(end) => end,
        None if remaining.len() > budget => return Err(MetadataError::Bounds),
        None => return Err(MetadataError::UnterminatedString),
    };
    *total = total.checked_add(end).ok_or(MetadataError::Bounds)?;
    Ok(&remaining[..end])
}

fn string_table<'a>(
    bytes: &'a [u8],
    headers: &[ProgramHeader],
    address: u64,
    size: u64,
) -> Result<&'a [u8], MetadataError> {
    let end = address.checked_add(size).ok_or(MetadataError::Range)?;
    let mut found = None;
    for header in headers.iter().filter(|header| header.kind == 1) {
        let memory_end = header
            .virtual_address
            .checked_add(header.memory_size)
            .ok_or(MetadataError::Range)?;
        // Count every LOAD intersecting the requested interval, not only those
        // containing it in full. Even identical file translations are rejected:
        // the contract requires one unambiguous mapping. Zero-fill portions
        // compete too, but empty LOAD memory ranges map no bytes.
        let intersects = header.memory_size != 0
            && if size == 0 {
                header.virtual_address <= address && address < memory_end
            } else {
                header.virtual_address < end && address < memory_end
            };
        if !intersects {
            continue;
        }
        if found.is_some() {
            return Err(MetadataError::StringTableMapping);
        }
        let file_end = header
            .virtual_address
            .checked_add(header.file_size)
            .ok_or(MetadataError::Range)?;
        if address < header.virtual_address || address >= file_end || end > file_end {
            return Err(MetadataError::StringTableMapping);
        }
        let offset = header
            .offset
            .checked_add(address - header.virtual_address)
            .ok_or(MetadataError::Range)?;
        found = Some(range(bytes, offset, size)?);
    }
    found.ok_or(MetadataError::StringTableMapping)
}

/// Extract bounded ELF64 little-endian x86-64 metadata from supplied bytes.
///
/// Only the ELF and program headers determine the result. Section tables are
/// neither traversed nor required. String bytes remain borrowed and unnormalized;
/// unknown metadata and data after DT_NULL remain visible. Duplicate STRTAB/STRSZ
/// fields refuse, whereas repeated NEEDED/SONAME/RPATH/RUNPATH remain descriptive.
/// Success establishes no provenance, safe resolution, native closure or right
/// to load. No program, loader, filesystem, environment or device is consulted.
///
/// # Errors
///
/// Returns a fixed [`MetadataError`] for unsupported formats, malformed or
/// overflowing ranges, ambiguous string tables, missing terminators and resource
/// limits. Metadata reservations are fallible; this cannot prevent process-wide
/// allocator or kernel out-of-memory termination outside those reservations.
pub fn inspect(bytes: &[u8]) -> Result<ElfMetadata<'_>, MetadataError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(MetadataError::Bounds);
    }
    let ident_bytes = bytes.get(..16).ok_or(MetadataError::Header)?;
    if ident_bytes.get(..4) != Some(b"\x7fELF") {
        return Err(MetadataError::Header);
    }
    if ident_bytes[4] != 2 || ident_bytes[5] != 1 || !matches!(ident_bytes[7], 0 | 3) {
        return Err(MetadataError::UnsupportedFormat);
    }
    if ident_bytes[6] != 1 {
        return Err(MetadataError::UnsupportedFormat);
    }
    let ident = parse_ident::<LittleEndian>(ident_bytes).map_err(|_| MetadataError::Header)?;
    let header = FileHeader::parse_tail(ident, bytes.get(16..64).ok_or(MetadataError::Header)?)
        .map_err(|_| MetadataError::Header)?;
    if header.e_machine != 62 || !matches!(header.e_type, 2 | 3) || header.version != 1 {
        return Err(MetadataError::UnsupportedFormat);
    }
    if header.e_ehsize != 64 || header.e_phentsize != 56 || header.e_phnum == 0xffff {
        return Err(MetadataError::HeaderLayout);
    }
    let count = usize::from(header.e_phnum);
    if count > MAX_PROGRAM_HEADERS {
        return Err(MetadataError::Bounds);
    }
    if count > 0 && header.e_phoff < 64 {
        return Err(MetadataError::Range);
    }
    let ph_bytes = range(bytes, header.e_phoff, u64::from(header.e_phnum) * 56)?;
    let mut headers = reserved(count)?;
    let mut interpreter_segment = None;
    let mut dynamic_segment = None;
    let mut notices = reserved(MAX_PROGRAM_HEADERS + MAX_DYNAMIC_ENTRIES * 2 + 2)?;
    if header.e_flags != 0 {
        notices.push(Notice::HeaderFlags);
    }
    for index in 0..count {
        let mut offset = index * 56;
        let ph = elf::segment::ProgramHeader::parse_at(
            LittleEndian,
            Class::ELF64,
            &mut offset,
            ph_bytes,
        )
        .map_err(|_| MetadataError::Range)?;
        if ph.p_type != 0 {
            let segment = range(bytes, ph.p_offset, ph.p_filesz)?;
            if ph.p_type == 1
                && (ph.p_filesz > ph.p_memsz || ph.p_vaddr.checked_add(ph.p_memsz).is_none())
            {
                return Err(MetadataError::Range);
            }
            match ph.p_type {
                2 => {
                    if dynamic_segment.replace(segment).is_some() {
                        return Err(MetadataError::DuplicateSegment);
                    }
                }
                3 => {
                    if interpreter_segment.replace(segment).is_some() {
                        return Err(MetadataError::DuplicateSegment);
                    }
                }
                1 | 4..=7 | 0x6474e550..=0x6474e553 => {}
                kind => notices.push(Notice::UnknownProgramHeader { index, kind }),
            }
        }
        headers.push(ProgramHeader {
            kind: ph.p_type,
            flags: ph.p_flags,
            offset: ph.p_offset,
            virtual_address: ph.p_vaddr,
            physical_address: ph.p_paddr,
            file_size: ph.p_filesz,
            memory_size: ph.p_memsz,
            alignment: ph.p_align,
        });
    }
    let mut total = 0;
    let interpreter = match interpreter_segment {
        Some(segment) => {
            if segment.len() > MAX_STRING_BYTES + 1 {
                return Err(MetadataError::Bounds);
            }
            let value = referenced_string(segment, 0, &mut total)?;
            if value.len() + 1 != segment.len() {
                return Err(MetadataError::Range);
            }
            Some(value)
        }
        None => None,
    };
    let mut entries = Vec::new();
    let mut strings = Vec::new();
    let mut terminator_index = None;
    if let Some(segment) = dynamic_segment {
        if segment.len() / 16 > MAX_DYNAMIC_ENTRIES {
            return Err(MetadataError::Bounds);
        }
        if segment.len() % 16 != 0 {
            return Err(MetadataError::Range);
        }
        entries = reserved(segment.len() / 16)?;
        for index in 0..segment.len() / 16 {
            let mut offset = index * 16;
            let entry =
                elf::dynamic::Dyn::parse_at(LittleEndian, Class::ELF64, &mut offset, segment)
                    .map_err(|_| MetadataError::Range)?;
            entries.push(DynamicEntry {
                tag: entry.d_tag,
                value: entry.d_val(),
            });
            if entry.d_tag == 0 && terminator_index.is_none() {
                terminator_index = Some(index);
            }
            if !named_dynamic_tag(entry.d_tag) {
                notices.push(Notice::UnknownDynamicTag {
                    index,
                    tag: entry.d_tag,
                });
            } else if !matches!(entry.d_tag, 0 | 1 | 5 | 10 | 14) {
                notices.push(Notice::UninterpretedDynamicTag {
                    index,
                    tag: entry.d_tag,
                });
            }
        }
        let end = terminator_index.ok_or(MetadataError::DynamicTerminator)?;
        if end + 1 < entries.len() {
            notices.push(Notice::TrailingDynamicEntries);
        }
        let active = &entries[..end];
        let reference_count = active
            .iter()
            .filter(|entry| string_kind(entry.tag).is_some())
            .count();
        if reference_count + usize::from(interpreter.is_some()) > MAX_STRING_REFERENCES {
            return Err(MetadataError::Bounds);
        }
        let mut address = None;
        let mut size = None;
        for entry in active {
            let field = match entry.tag {
                5 => &mut address,
                10 => &mut size,
                _ => continue,
            };
            if field.replace(entry.value).is_some() {
                return Err(MetadataError::DuplicateStringTable);
            }
        }
        let table = match (address, size) {
            (Some(address), Some(size)) => Some(string_table(bytes, &headers, address, size)?),
            (None, None) if reference_count == 0 => None,
            _ => return Err(MetadataError::MissingStringTable),
        };
        strings = reserved(reference_count)?;
        for (index, entry) in active.iter().enumerate() {
            let Some(kind) = string_kind(entry.tag) else {
                continue;
            };
            let value = referenced_string(
                table.ok_or(MetadataError::MissingStringTable)?,
                entry.value,
                &mut total,
            )?;
            if strings
                .iter()
                .any(|previous: &DynamicString<'_>| previous.kind == kind)
            {
                notices.push(Notice::RepeatedStringTag {
                    index,
                    tag: entry.tag,
                });
            }
            strings.push(DynamicString {
                kind,
                entry_index: index,
                bytes: value,
            });
        }
    }
    Ok(ElfMetadata {
        header: Header {
            class: 2,
            byte_order: 1,
            version: header.version,
            os_abi: header.osabi,
            abi_version: header.abiversion,
            file_type: header.e_type,
            machine: header.e_machine,
            flags: header.e_flags,
        },
        program_headers: headers,
        interpreter,
        strings,
        dynamic_bytes: dynamic_segment,
        dynamic_entries: entries,
        terminator_index,
        notices,
    })
}

#[cfg(test)]
mod tests;
