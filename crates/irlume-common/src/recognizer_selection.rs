// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Provenance of the administrator's recognizer selection, not placement.

use serde::{Deserialize, Deserializer, Serialize};

/// The source observed when the daemon resolved its governing selection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecognizerSelectionSource {
    /// No authoritative selection value was present.
    Default,
    /// The selection came from, or was refused in, the settings snapshot.
    Settings,
    /// An environment value was authoritative, whether valid or invalid.
    Environment,
    /// The member was missing or contained a future string value.
    #[default]
    Unknown,
}

impl<'de> Deserialize<'de> for RecognizerSelectionSource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Require a JSON string, not an externally tagged enum object. Unknown
        // strings are discarded rather than becoming diagnostic text.
        Ok(match String::deserialize(deserializer)?.as_str() {
            "default" => Self::Default,
            "settings" => Self::Settings,
            "environment" => Self::Environment,
            _ => Self::Unknown,
        })
    }
}

/// A selection parsing issue, independent of accelerator availability.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecognizerSelectionIssue {
    /// The authoritative selection was understood, including genuine absence.
    None,
    /// An authoritative value or assignment was not recognized.
    InvalidValue,
    /// The settings snapshot attempted the selection key more than once.
    DuplicateKey,
    /// The settings snapshot could not be read or decoded as UTF-8.
    UnreadableSettings,
    /// The member was missing or contained a future string value.
    #[default]
    Unknown,
}

impl<'de> Deserialize<'de> for RecognizerSelectionIssue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match String::deserialize(deserializer)?.as_str() {
            "none" => Self::None,
            "invalid_value" => Self::InvalidValue,
            "duplicate_key" => Self::DuplicateKey,
            "unreadable_settings" => Self::UnreadableSettings,
            _ => Self::Unknown,
        })
    }
}

/// Value-redacted provenance for one successfully published engine selection.
///
/// Missing members are unknown, not evidence of default policy or valid input.
/// This describes selection intent, never ranking, eligibility or execution.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RecognizerSelectionProvenance {
    /// The observed authoritative source, or explicit default selection.
    pub source: RecognizerSelectionSource,
    /// The observed parsing result, or unknown when not reported.
    pub issue: RecognizerSelectionIssue,
}

impl<'de> Deserialize<'de> for RecognizerSelectionProvenance {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Object;

        impl<'de> serde::de::Visitor<'de> for Object {
            type Value = RecognizerSelectionProvenance;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a selection provenance object")
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut source = None;
                let mut issue = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "source" => {
                            if source.is_some() {
                                return Err(serde::de::Error::duplicate_field("source"));
                            }
                            source = Some(map.next_value()?);
                        }
                        "issue" => {
                            if issue.is_some() {
                                return Err(serde::de::Error::duplicate_field("issue"));
                            }
                            issue = Some(map.next_value()?);
                        }
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(RecognizerSelectionProvenance {
                    source: source.unwrap_or_default(),
                    issue: issue.unwrap_or_default(),
                })
            }
        }

        deserializer.deserialize_map(Object)
    }
}

#[cfg(test)]
mod tests;
