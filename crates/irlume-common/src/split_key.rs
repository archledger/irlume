// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
//! Canonical split-pair key text and typed ordering (ADR-0032 §4.1.1).
//!
//! The typed form is authoritative: canonical text exists where a key must be
//! stored (`cameras.conf`'s `split_pair`), and text equality equals typed
//! equality because the encoding is injective and the decoder rejects
//! non-canonical input. Text order is never used for ranking; the `Ord`
//! implementations here are the comparator of ADR-0032 §3: identity,
//! controller, root-hub domain (table order, which is bytewise canonical-text
//! order), then the port chain element-wise as numbers with a proper prefix
//! sorting before the longer chain.

use std::fmt;

/// Root-hub protocol domain as the schema records it (ADR-0032 §4.1.1).
///
/// Declaration order is the §4.1.1 table order (`superspeed` = 0,
/// `usb2` = 1), which is also the bytewise order of the canonical text, so
/// derived `Ord` is the specified comparator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SplitDomain {
    /// SuperSpeed root hub, canonical text `superspeed`.
    SuperSpeed,
    /// USB2 root hub, canonical text `usb2`.
    Usb2,
}

/// One side of a split pair: the durable key of §2, as stored.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SplitUnitKey {
    /// Binding identity in the existing `vid:pid[:serial]` form.
    pub identity: String,
    /// Controller identity (PCI address text).
    pub controller: String,
    /// Root-hub protocol domain.
    pub domain: SplitDomain,
    /// Relative port chain, each element 1..=255.
    pub ports: Vec<u8>,
}

/// A role-labelled split pair key: RGB unit then IR unit (ADR-0032 §4.1.1).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SplitPairKey {
    /// The RGB side.
    pub rgb: SplitUnitKey,
    /// The IR side.
    pub ir: SplitUnitKey,
}

/// Why canonical key text was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The class tag is not `split1`.
    BadClassTag,
    /// A unit does not have exactly four `|`-separated fields.
    BadUnitShape,
    /// A field decoded to empty where non-empty is required.
    EmptyField,
    /// The domain text is not `usb2` or `superspeed`.
    BadDomain,
    /// The ports text is not canonical (`1..=255`, dotted, no leading zeros).
    BadPorts,
    /// `%XX` used a lowercase hex digit.
    LowercaseHex,
    /// `%XX` escaped a byte the scheme leaves unescaped.
    UnnecessaryEscape,
    /// `%` not followed by two hex digits, or trailing garbage.
    BadEscape,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadClassTag => "the class tag is not split1",
            Self::BadUnitShape => "a unit does not carry exactly four fields",
            Self::EmptyField => "a required field is empty",
            Self::BadDomain => "the domain text is not usb2 or superspeed",
            Self::BadPorts => "the port chain text is not canonical",
            Self::LowercaseHex => "a percent escape uses lowercase hex",
            Self::UnnecessaryEscape => "a percent escape covers a byte that needs none",
            Self::BadEscape => "a percent escape is incomplete",
        })
    }
}

fn is_safe_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b':' | b'.' | b'_' | b'-')
}

/// Percent-encode `text` per §4.1.1 (safe set `A-Z a-z 0-9 : . _ -`).
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for &b in text.as_bytes() {
        if is_safe_byte(b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Decode canonical percent-encoding; reject lowercase hex and escapes that
/// cover a safe byte, so each text has exactly one encoding.
fn percent_decode(text: &str) -> Result<String, KeyError> {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = *bytes.get(i + 1).ok_or(KeyError::BadEscape)?;
            let lo = *bytes.get(i + 2).ok_or(KeyError::BadEscape)?;
            let hex = |c: u8| match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'A'..=b'F' => Some(c - b'A' + 10),
                b'a'..=b'f' => Some(c - b'a' + 10),
                _ => None,
            };
            let (Some(h), Some(l)) = (hex(hi), hex(lo)) else {
                return Err(KeyError::BadEscape);
            };
            if hi.is_ascii_lowercase() || lo.is_ascii_lowercase() {
                return Err(KeyError::LowercaseHex);
            }
            let value = (h << 4) | l;
            if is_safe_byte(value) {
                return Err(KeyError::UnnecessaryEscape);
            }
            out.push(value);
            i += 3;
        } else if is_safe_byte(bytes[i]) {
            // Only safe bytes may appear unescaped: otherwise one key would
            // have several texts and text equality would stop meaning typed
            // equality (ADR-0032 §4.1.1).
            out.push(bytes[i]);
            i += 1;
        } else {
            return Err(KeyError::BadEscape);
        }
    }
    String::from_utf8(out).map_err(|_| KeyError::BadEscape)
}

/// Canonical ports text: decimal elements 1..=255, dotted, no leading zeros.
pub fn format_ports_text(ports: &[u8]) -> String {
    let mut out = String::new();
    for (i, p) in ports.iter().enumerate() {
        if i > 0 {
            out.push('.');
        }
        out.push_str(&p.to_string());
    }
    out
}

/// Parse canonical ports text (ADR-0032 §4.1.1).
///
/// # Errors
/// [`KeyError::BadPorts`] for anything non-canonical.
pub fn parse_ports_text(text: &str) -> Result<Vec<u8>, KeyError> {
    let mut ports = Vec::new();
    for part in text.split('.') {
        if part.is_empty()
            || !part.bytes().all(|b| b.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return Err(KeyError::BadPorts);
        }
        let value: u16 = part.parse().map_err(|_| KeyError::BadPorts)?;
        if !(1..=255).contains(&value) {
            return Err(KeyError::BadPorts);
        }
        ports.push(value as u8);
    }
    Ok(ports)
}

impl SplitDomain {
    /// The canonical domain text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SuperSpeed => "superspeed",
            Self::Usb2 => "usb2",
        }
    }

    /// Parse the canonical domain text; anything else (including `ss`) is
    /// rejected so each domain has exactly one schema spelling.
    ///
    /// # Errors
    /// [`KeyError::BadDomain`] for any text other than `usb2`/`superspeed`.
    pub fn parse_canonical(text: &str) -> Result<Self, KeyError> {
        match text {
            "superspeed" => Ok(Self::SuperSpeed),
            "usb2" => Ok(Self::Usb2),
            _ => Err(KeyError::BadDomain),
        }
    }
}

impl SplitUnitKey {
    /// Canonical unit text: four percent-encoded fields separated by `|`.
    pub fn format_canonical(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            percent_encode(&self.identity),
            percent_encode(&self.controller),
            self.domain.as_str(),
            format_ports_text(&self.ports),
        )
    }

    /// Parse canonical unit text. `|` and `;` are always escaped in values,
    /// so splitting the raw text at those bytes is unambiguous.
    ///
    /// # Errors
    /// [`KeyError`] when the shape, encoding, domain text or ports text is
    /// not canonical.
    pub fn parse_canonical(text: &str) -> Result<Self, KeyError> {
        let fields: Vec<&str> = text.split('|').collect();
        if fields.len() != 4 {
            return Err(KeyError::BadUnitShape);
        }
        let identity = percent_decode(fields[0])?;
        let controller = percent_decode(fields[1])?;
        if identity.is_empty() || controller.is_empty() {
            return Err(KeyError::EmptyField);
        }
        Ok(Self {
            identity,
            controller,
            domain: SplitDomain::parse_canonical(fields[2])?,
            ports: parse_ports_text(fields[3])?,
        })
    }
}

impl SplitPairKey {
    /// Canonical pair text: `split1;<rgb unit>;<ir unit>`.
    pub fn format_canonical(&self) -> String {
        format!(
            "split1;{};{}",
            self.rgb.format_canonical(),
            self.ir.format_canonical()
        )
    }

    /// Parse canonical pair text.
    ///
    /// # Errors
    /// [`KeyError`] when the class tag, unit shape or any field is not
    /// canonical.
    pub fn parse_canonical(text: &str) -> Result<Self, KeyError> {
        let rest = text.strip_prefix("split1;").ok_or(KeyError::BadClassTag)?;
        let (rgb, ir) = rest.split_once(';').ok_or(KeyError::BadUnitShape)?;
        Ok(Self {
            rgb: SplitUnitKey::parse_canonical(rgb)?,
            ir: SplitUnitKey::parse_canonical(ir)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> &'static str {
        "split1;5986:2113:200901010001|0000:00:14.0|usb2|8;5986:1141:200901010001|0000:00:14.0|usb2|5"
    }

    fn example_key() -> SplitPairKey {
        SplitPairKey {
            rgb: SplitUnitKey {
                identity: "5986:2113:200901010001".into(),
                controller: "0000:00:14.0".into(),
                domain: SplitDomain::Usb2,
                ports: vec![8],
            },
            ir: SplitUnitKey {
                identity: "5986:1141:200901010001".into(),
                controller: "0000:00:14.0".into(),
                domain: SplitDomain::Usb2,
                ports: vec![5],
            },
        }
    }

    #[test]
    fn the_adr_example_round_trips() {
        let key = SplitPairKey::parse_canonical(example()).expect("example parses");
        assert_eq!(key, example_key());
        assert_eq!(key.format_canonical(), example());
    }

    #[test]
    fn the_encoding_is_injective_for_separators() {
        let one = SplitUnitKey {
            identity: "1:2:a|b;c=d%e f".into(),
            controller: "0000:00:14.0".into(),
            domain: SplitDomain::SuperSpeed,
            ports: vec![1, 2],
        };
        let two = SplitUnitKey {
            identity: "1:2:a".into(),
            controller: "0000:00:14.0".into(),
            domain: SplitDomain::SuperSpeed,
            ports: vec![1, 2],
        };
        let text = one.format_canonical();
        assert!(!text.contains("a|b"));
        assert_eq!(SplitUnitKey::parse_canonical(&text).unwrap(), one);
        assert_ne!(text, two.format_canonical());
    }

    #[test]
    fn non_canonical_text_is_rejected() {
        let bad = [
            "split1;5986:2113:x%2f|0000:00:14.0|usb2|8;5986:1141:y|0000:00:14.0|usb2|5",
            "split1;5986:2113:x%3a|0000:00:14.0|usb2|8;5986:1141:y|0000:00:14.0|usb2|5",
            "split1;5986:2113:x|0000:00:14.0|usb2|08;5986:1141:y|0000:00:14.0|usb2|5",
            "split1;5986:2113:x|0000:00:14.0|usb2|0;5986:1141:y|0000:00:14.0|usb2|5",
            "split1;5986:2113:x|0000:00:14.0|usb2|256;5986:1141:y|0000:00:14.0|usb2|5",
            "split1;5986:2113:x|0000:00:14.0|usb2|;5986:1141:y|0000:00:14.0|usb2|5",
            "split1;5986:2113:x|0000:00:14.0|ss|8;5986:1141:y|0000:00:14.0|usb2|5",
            "split2;5986:2113:x|0000:00:14.0|usb2|8;5986:1141:y|0000:00:14.0|usb2|5",
            "split1;5986:2113:x|0000:00:14.0|usb2|8;5986:1141:y|0000:00:14.0|usb2",
            "split1;|0000:00:14.0|usb2|8;5986:1141:y|0000:00:14.0|usb2|5",
            "split1;a b|c|usb2|8;x|c|usb2|5",
            "split1;a;b|c|usb2|8;x|c|usb2|5",
            "split1;a=b|c|usb2|8;x|c|usb2|5",
        ];
        for text in bad {
            assert!(
                SplitPairKey::parse_canonical(text).is_err(),
                "must reject {text}"
            );
        }
    }

    #[test]
    fn port_order_is_numeric_not_textual() {
        let at = |ports: Vec<u8>| SplitUnitKey {
            identity: "x".into(),
            controller: "c".into(),
            domain: SplitDomain::Usb2,
            ports,
        };
        assert!(at(vec![8]) < at(vec![10]));
    }

    #[test]
    fn a_proper_prefix_sorts_before_the_longer_chain() {
        let at = |ports: Vec<u8>| SplitUnitKey {
            identity: "x".into(),
            controller: "c".into(),
            domain: SplitDomain::Usb2,
            ports,
        };
        assert!(at(vec![8]) < at(vec![8, 1]));
    }

    #[test]
    fn domain_order_is_the_table_order() {
        assert!(SplitDomain::SuperSpeed < SplitDomain::Usb2);
    }

    #[test]
    fn pair_keys_compare_rgb_then_ir() {
        let mut key = example_key();
        let original = key.clone();
        key.ir.ports = vec![6];
        assert!(original < key);
        key.ir = original.ir.clone();
        key.rgb.ports = vec![9];
        assert!(original < key);
    }
}
