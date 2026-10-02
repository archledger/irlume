// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! The split-authorization generation file (ADR-0032 §4.1.2).
//!
//! A generation is immutable after publication: line-oriented `key=value`
//! under the same unsafe-value rules as `cameras.conf`, mandatory `version=1`,
//! and indexed records `pair.<i>.{rgb,ir}_{identity,path,controller,domain,ports}`
//! with `<i>` contiguous from 0. Record order is overlap-resolution priority,
//! not an account preference. The parser is pure and scans the whole file so
//! every problem is reported; a missing or unrecognized component is Malformed,
//! never a wildcard.

use crate::split_key::{format_ports_text, parse_ports_text, SplitDomain};

/// Most records one generation may hold (ADR-0032 §4.1.2).
pub const MAX_RECORDS: usize = 16;
/// Longest `key=value` line, in bytes (ADR-0032 §4.1.2).
pub const MAX_LINE_BYTES: usize = 1024;
/// Longest generation file, in bytes (ADR-0032 §4.1.2).
pub const MAX_FILE_BYTES: usize = 65536;
/// Longest port chain (ADR-0032 §4.1.2: a root port plus one element per hub).
pub const MAX_PORT_ELEMENTS: usize = 6;

/// One side of an authorization record (ADR-0032 §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SideFields {
    /// Binding identity `vid:pid[:serial]`.
    pub identity: String,
    /// Selected node path.
    pub path: String,
    /// Controller identity.
    pub controller: String,
    /// Root-hub protocol domain.
    pub domain: SplitDomain,
    /// Relative port chain.
    pub ports: Vec<u8>,
}

/// One ordered authorization record: RGB side then IR side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationRecord {
    /// The RGB side.
    pub rgb: SideFields,
    /// The IR side.
    pub ir: SideFields,
}

/// Why a generation could not be written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaError {
    /// More than [`MAX_RECORDS`] records.
    TooManyRecords,
    /// A line exceeds [`MAX_LINE_BYTES`].
    LineTooLong,
    /// The file exceeds [`MAX_FILE_BYTES`].
    FileTooLong,
    /// A port chain exceeds [`MAX_PORT_ELEMENTS`] or is not canonical.
    BadPorts,
    /// A required field is empty or would not read back as one line.
    InvalidField,
}

/// What one pure read of a generation established (ADR-0032 §4.1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenerationObservation {
    /// The whole file parsed; records keep their input order.
    Valid {
        /// The ordered authorization records.
        records: Vec<AuthorizationRecord>,
    },
    /// The file breaks the grammar; every problem found is listed.
    Malformed {
        /// Human-readable problems, in file order.
        problems: Vec<String>,
    },
}

const SIDE_KEYS: [&str; 5] = ["identity", "path", "controller", "domain", "ports"];

fn record_key(i: usize, side: &str, field: &str) -> String {
    format!("pair.{i}.{side}_{field}")
}

/// Serialize records into generation-file text.
///
/// # Errors
/// [`SchemaError`] when a bound or field rule would be violated; nothing is
/// written unless the whole text is valid.
pub fn serialize_generation(records: &[AuthorizationRecord]) -> Result<String, SchemaError> {
    if records.len() > MAX_RECORDS {
        return Err(SchemaError::TooManyRecords);
    }
    let mut out = String::from("version=1\n");
    for (i, record) in records.iter().enumerate() {
        for (side, fields) in [("rgb", &record.rgb), ("ir", &record.ir)] {
            if fields.identity.is_empty()
                || fields.path.is_empty()
                || fields.controller.is_empty()
                || [&fields.identity, &fields.path, &fields.controller]
                    .iter()
                    .any(|v| !value_reads_back_as_one_line(v))
            {
                return Err(SchemaError::InvalidField);
            }
            if fields.ports.is_empty()
                || fields.ports.len() > MAX_PORT_ELEMENTS
                || fields.ports.iter().any(|p| *p == 0)
            {
                return Err(SchemaError::BadPorts);
            }
            for (field, value) in [
                ("identity", fields.identity.clone()),
                ("path", fields.path.clone()),
                ("controller", fields.controller.clone()),
                ("domain", fields.domain.as_str().to_owned()),
                ("ports", format_ports_text(&fields.ports)),
            ] {
                let line = format!("{}={}\n", record_key(i, side, &field), value);
                if line.len() > MAX_LINE_BYTES {
                    return Err(SchemaError::LineTooLong);
                }
                out.push_str(&line);
            }
        }
    }
    if out.len() > MAX_FILE_BYTES {
        return Err(SchemaError::FileTooLong);
    }
    Ok(out)
}

/// Whether `value` reads back as the same single line (the `cameras.conf`
/// unsafe-value rule).
fn value_reads_back_as_one_line(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && !value.chars().any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'))
}

/// Parse generation-file text. Pure; never returns an I/O state.
#[must_use]
pub fn parse_generation(text: &str) -> GenerationObservation {
    let mut problems: Vec<String> = Vec::new();
    if text.len() > MAX_FILE_BYTES {
        problems.push(format!("the file is over {MAX_FILE_BYTES} bytes"));
        return GenerationObservation::Malformed { problems };
    }
    // (index, side index 0=rgb 1=ir, field index) -> value.
    let mut seen: Vec<[[Option<String>; 5]; 2]> = Vec::new();
    let mut max_index: Option<usize> = None;
    let mut version_lines = 0usize;
    for (number, raw) in text.lines().enumerate() {
        let line_no = number + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if raw.len() > MAX_LINE_BYTES {
            problems.push(format!("line {line_no} is over {MAX_LINE_BYTES} bytes"));
        }
        let Some((key, value)) = line.split_once('=') else {
            problems.push(format!("line {line_no} has no '='"));
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if key == "version" {
            version_lines += 1;
            if value != "1" {
                problems.push(format!("line {line_no}: version is not 1"));
            }
            continue;
        }
        let Some(rest) = key.strip_prefix("pair.") else {
            problems.push(format!("line {line_no}: unknown key '{key}'"));
            continue;
        };
        let Some((index_text, tail)) = rest.split_once('.') else {
            problems.push(format!("line {line_no}: unknown key '{key}'"));
            continue;
        };
        // Indices are canonical decimals so one record has one spelling.
        if index_text.is_empty()
            || !index_text.bytes().all(|b| b.is_ascii_digit())
            || (index_text.len() > 1 && index_text.starts_with('0'))
        {
            problems.push(format!("line {line_no}: record index is not canonical"));
            continue;
        }
        let index: usize = match index_text.parse() {
            Ok(v) => v,
            Err(_) => {
                problems.push(format!("line {line_no}: record index is out of range"));
                continue;
            }
        };
        if index >= MAX_RECORDS {
            problems.push(format!("line {line_no}: record index is over {MAX_RECORDS}"));
            continue;
        }
        let Some((side, field)) = tail.split_once('_') else {
            problems.push(format!("line {line_no}: unknown key '{key}'"));
            continue;
        };
        let (Some(side_idx), Some(field_idx)) = (
            match side {
                "rgb" => Some(0usize),
                "ir" => Some(1),
                _ => None,
            },
            SIDE_KEYS.iter().position(|f| *f == field),
        ) else {
            problems.push(format!("line {line_no}: unknown key '{key}'"));
            continue;
        };
        if seen.len() <= index {
            seen.resize(index + 1, [[None, None, None, None, None], [None, None, None, None, None]]);
        }
        if seen[index][side_idx][field_idx].is_some() {
            problems.push(format!("line {line_no}: '{key}' is set more than once"));
            continue;
        }
        seen[index][side_idx][field_idx] = Some(value.to_owned());
        max_index = Some(max_index.map_or(index, |m| m.max(index)));
    }
    if version_lines != 1 {
        problems.push(format!("version must appear exactly once, found {version_lines}"));
    }
    let count = max_index.map_or(0, |m| m + 1);
    if seen.len() != count {
        problems.push("record indices are not contiguous from 0".to_owned());
    }
    let mut records = Vec::new();
    for index in 0..count {
        let mut sides: [Option<SideFields>; 2] = [None, None];
        for side_idx in 0..2 {
            let mut fields: [Option<String>; 5] = [None, None, None, None, None];
            for field_idx in 0..5 {
                fields[field_idx] = seen[index][side_idx][field_idx].clone();
            }
            let mut missing = false;
            for (field_idx, field) in SIDE_KEYS.iter().enumerate() {
                match &fields[field_idx] {
                    Some(v) if value_reads_back_as_one_line(v) => {}
                    _ => {
                        problems.push(format!(
                            "pair.{index}.{}_{field} is missing or invalid",
                            if side_idx == 0 { "rgb" } else { "ir" }
                        ));
                        missing = true;
                    }
                }
            }
            if missing {
                continue;
            }
            let domain = match SplitDomain::parse_canonical(fields[3].as_deref().unwrap_or("")) {
                Ok(domain) => domain,
                Err(_) => {
                    problems.push(format!(
                        "pair.{index}.{}_{DOMAIN_FIELD} is not canonical",
                        if side_idx == 0 { "rgb" } else { "ir" }
                    ));
                    continue;
                }
            };
            let ports = match parse_ports_text(fields[4].as_deref().unwrap_or("")) {
                Ok(ports) if !ports.is_empty() && ports.len() <= MAX_PORT_ELEMENTS => ports,
                _ => {
                    problems.push(format!(
                        "pair.{index}.{}_{PORTS_FIELD} is not canonical",
                        if side_idx == 0 { "rgb" } else { "ir" }
                    ));
                    continue;
                }
            };
            sides[side_idx] = Some(SideFields {
                identity: fields[0].clone().unwrap_or_default(),
                path: fields[1].clone().unwrap_or_default(),
                controller: fields[2].clone().unwrap_or_default(),
                domain,
                ports,
            });
        }
        match (sides[0].take(), sides[1].take()) {
            (Some(rgb), Some(ir)) => records.push(AuthorizationRecord { rgb, ir }),
            _ => {}
        }
    }
    if problems.is_empty() {
        GenerationObservation::Valid { records }
    } else {
        GenerationObservation::Malformed { problems }
    }
}

const DOMAIN_FIELD: &str = "domain";
const PORTS_FIELD: &str = "ports";

#[cfg(test)]
mod tests {
    use super::*;

    fn side(identity: &str, path: &str, ports: &[u8], domain: SplitDomain) -> SideFields {
        SideFields {
            identity: identity.into(),
            path: path.into(),
            controller: "0000:00:14.0".into(),
            domain,
            ports: ports.to_vec(),
        }
    }

    fn record(rgb_id: &str, ir_id: &str) -> AuthorizationRecord {
        AuthorizationRecord {
            rgb: side(rgb_id, "/dev/video0", &[8], SplitDomain::Usb2),
            ir: side(ir_id, "/dev/video1", &[5], SplitDomain::Usb2),
        }
    }

    #[test]
    fn a_valid_generation_round_trips() {
        let records = vec![record("5986:2113:s1", "5986:1141:s2"), record("a:1", "b:2")];
        let text = serialize_generation(&records).expect("serializes");
        assert_eq!(
            parse_generation(&text),
            GenerationObservation::Valid {
                records: records.clone()
            }
        );
    }

    #[test]
    fn a_missing_field_is_malformed() {
        let records = vec![record("a:1", "b:2")];
        let text = serialize_generation(&records).unwrap();
        let broken: String = text
            .lines()
            .filter(|l| !l.starts_with("pair.0.ir_ports"))
            .map(|l| format!("{l}\n"))
            .collect();
        let GenerationObservation::Malformed { problems } = parse_generation(&broken) else {
            panic!("missing field must be Malformed");
        };
        assert!(!problems.is_empty());
    }

    #[test]
    fn an_unknown_key_is_malformed() {
        let text = "version=1\npair.0.rgb_identity=a:1\npair.0.rgb_path=/dev/video0\n\
pair.0.rgb_controller=0000:00:14.0\npair.0.rgb_domain=usb2\npair.0.rgb_ports=8\n\
pair.0.ir_identity=b:2\npair.0.ir_path=/dev/video1\npair.0.ir_controller=0000:00:14.0\n\
pair.0.ir_domain=usb2\npair.0.ir_ports=5\nsurprise=yes\n";
        assert!(matches!(
            parse_generation(text),
            GenerationObservation::Malformed { .. }
        ));
    }

    #[test]
    fn a_wrong_version_is_malformed() {
        let records = vec![record("a:1", "b:2")];
        let text = serialize_generation(&records).unwrap().replace("version=1", "version=2");
        assert!(matches!(
            parse_generation(&text),
            GenerationObservation::Malformed { .. }
        ));
        let no_version = serialize_generation(&records)
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("version="))
            .map(|l| format!("{l}\n"))
            .collect::<String>();
        assert!(matches!(
            parse_generation(&no_version),
            GenerationObservation::Malformed { .. }
        ));
    }

    #[test]
    fn a_gap_in_indices_is_malformed() {
        let text = "version=1\npair.2.rgb_identity=a:1\npair.2.rgb_path=/dev/video0\n\
pair.2.rgb_controller=0000:00:14.0\npair.2.rgb_domain=usb2\npair.2.rgb_ports=8\n\
pair.2.ir_identity=b:2\npair.2.ir_path=/dev/video1\npair.2.ir_controller=0000:00:14.0\n\
pair.2.ir_domain=usb2\npair.2.ir_ports=5\n";
        assert!(matches!(
            parse_generation(text),
            GenerationObservation::Malformed { .. }
        ));
    }

    #[test]
    fn bounds_are_enforced() {
        let many: Vec<AuthorizationRecord> = (0..17)
            .map(|i| record(&format!("a:{i}"), &format!("b:{i}")))
            .collect();
        assert!(matches!(
            serialize_generation(&many),
            Err(SchemaError::TooManyRecords)
        ));

        let long_identity = "x".repeat(1100);
        assert!(matches!(
            serialize_generation(&[record(&long_identity, "b:2")]),
            Err(SchemaError::LineTooLong)
        ));

        let many_ports: Vec<u8> = (1..=7).collect();
        let mut one = record("a:1", "b:2");
        one.rgb.ports = many_ports;
        assert!(matches!(
            serialize_generation(&[one]),
            Err(SchemaError::BadPorts)
        ));

        let fat = format!("{}{}", "version=1\n", "a=b\n".repeat(20000));
        assert!(matches!(
            parse_generation(&fat),
            GenerationObservation::Malformed { .. }
        ));
    }

    #[test]
    fn every_problem_is_reported() {
        let text = "version=1\npair.0.rgb_identity=\nnope=1\n";
        let GenerationObservation::Malformed { problems } = parse_generation(text) else {
            panic!("must be Malformed");
        };
        assert!(problems.len() >= 2, "got {problems:?}");
    }

    #[test]
    fn record_order_is_overlap_priority() {
        let records = vec![record("first:1", "first:2"), record("second:1", "second:2")];
        let text = serialize_generation(&records).unwrap();
        let GenerationObservation::Valid {
            records: parsed, ..
        } = parse_generation(&text)
        else {
            panic!("must be Valid");
        };
        assert_eq!(parsed[0].rgb.identity, "first:1");
        assert_eq!(parsed[1].rgb.identity, "second:1");
    }

    #[test]
    fn field_values_stay_single_line() {
        let mut one = record("a:1", "b:2");
        one.rgb.identity = "bad\nvalue".into();
        assert!(matches!(
            serialize_generation(&[one]),
            Err(SchemaError::InvalidField)
        ));
    }

    #[test]
    fn domain_text_is_canonical() {
        let text = "version=1\npair.0.rgb_identity=a:1\npair.0.rgb_path=/dev/video0\n\
pair.0.rgb_controller=0000:00:14.0\npair.0.rgb_domain=ss\npair.0.rgb_ports=8\n\
pair.0.ir_identity=b:2\npair.0.ir_path=/dev/video1\npair.0.ir_controller=0000:00:14.0\n\
pair.0.ir_domain=usb2\npair.0.ir_ports=5\n";
        assert!(matches!(
            parse_generation(text),
            GenerationObservation::Malformed { .. }
        ));
    }
}
