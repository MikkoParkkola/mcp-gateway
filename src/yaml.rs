// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway's one YAML seam (MIK-8425).
//!
//! Every YAML read and write goes through here, so the parser behind it can
//! be replaced in one place. Today the backend is `serde_yaml` 0.9.34. The
//! tree types are re-exported and the parse and write functions delegate,
//! keeping that crate's own behaviour. One function is the seam's own:
//! `to_json`, the tree-to-JSON conversion that `ImportedSkill.extra` uses.
//! A later stage swaps the backend behind this same surface.
//! `tests/fixtures/mik_8425_yaml/` records what the delegating functions must
//! reproduce, and the skills parser and registry tests pin `to_json`.
//! The seam's own `Error` (every function here except `figment_data`)
//! never prints the value that caused it (MIK-8425 B3); `figment_data`
//! returns figment's error, which `config/load_error.rs` (`from_figment`)
//! redacts.
//!
//! This file names nothing under `crate::`. Integration tests compile it
//! directly (`tests/common/yaml.rs`), so tests and the gateway always share
//! one implementation.
#![allow(
    dead_code,
    unused_imports,
    reason = "MIK-8425: consumers are routed through this seam in MIG.1b to MIG.1f; \
              until then parts of it have no caller. Integration-test crates compile their \
              own copy through tests/common/yaml.rs and never call all of it. Delete this \
              allow in MIG.2, when the swap re-examines the surface."
)]

use figment::Provider as _;
use figment::providers::{Format as _, Yaml};
use figment::value::{Dict, Map};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// The YAML tree and its mapping. They stay `serde_yaml`'s own until the
/// backend swap, which keeps routing a pure path rename.
pub(crate) use serde_yaml::{Mapping, Value};

/// The adapter's YAML error; its text never carries the value that caused it
/// (MIK-8425 B3, CWE-532), keeps the key path, expected type and line/column.
pub(crate) struct Error(serde_yaml::Error);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&redact_message(&self.0.to_string()))
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Error")
            .field(&redact_message(&self.0.to_string()))
            .finish()
    }
}

// No `source()`: a chain printer must not reach serde_yaml's unredacted text.
impl std::error::Error for Error {}

impl Error {
    /// Where the refusal points in the document, if the parser knows.
    pub(crate) fn location(&self) -> Option<Location> {
        self.0.location().map(|at| Location {
            line: at.line(),
            column: at.column(),
        })
    }
}

/// Where in a YAML document a refusal points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Location {
    line: usize,
    column: usize,
}

impl Location {
    /// The line of the refusal.
    pub(crate) fn line(&self) -> usize {
        self.line
    }

    /// The column of the refusal.
    pub(crate) fn column(&self) -> usize {
        self.column
    }
}

/// What serde puts between a quoted value and the type it wanted.
const EXPECTED: &str = ", expected ";

/// serde's marker before a variant name it did not recognise.
const VARIANT: &str = "unknown variant `";

/// `message` with any value serde quoted in it removed.
///
/// serde's own messages put the value between a fixed marker and the LAST
/// `, expected ` after it; a value may itself contain `, expected `, so the
/// first one is not the end of it. Every other message passes through:
/// libyaml's syntax problems are fixed strings, and the gateway's own refusals
/// name keys, never values.
pub(crate) fn redact_message(message: &str) -> String {
    // The EARLIEST marker is serde's own: a later one can only sit inside the
    // value, so choosing by marker kind first would cut at text the value
    // supplied and keep the value before it.
    let earliest = ["invalid type: ", "invalid value: ", VARIANT]
        .into_iter()
        .filter_map(|marker| message.find(marker).map(|at| (at, marker)))
        .min_by_key(|(at, _)| *at);
    let Some((start, marker)) = earliest else {
        return message.to_owned();
    };
    let from = start + marker.len();
    let tail = &message[from..];
    if marker == VARIANT {
        let rest = tail
            .rfind(EXPECTED)
            .map_or_else(|| location(tail), |cut| &tail[cut..]);
        return format!(
            "{}{}{rest}",
            &message[..start],
            VARIANT.trim_end_matches(" `")
        );
    }
    match tail.rfind(EXPECTED) {
        Some(cut) => format!(
            "{}{}{}",
            &message[..from],
            kind_word(&tail[..cut]),
            &tail[cut..]
        ),
        None => format!("{}a value{}", &message[..from], location(tail)),
    }
}

/// serde's description of a value, cut before the value: `string "x"` is
/// `string`. Only serde's own type words are kept; anything else is
/// verbatim input (serde's `Other`), so it becomes `a value`.
fn kind_word(unexpected: &str) -> &str {
    const SERDE_WORDS: [&str; 16] = [
        "boolean",
        "integer",
        "floating point",
        "character",
        "string",
        "byte array",
        "unit value",
        "Option value",
        "newtype struct",
        "sequence",
        "map",
        "enum",
        "unit variant",
        "newtype variant",
        "tuple variant",
        "struct variant",
    ];
    let word = unexpected
        .find(['"', '`', '[', '\''])
        .map_or(unexpected, |at| &unexpected[..at])
        .trim();
    SERDE_WORDS
        .into_iter()
        .find(|known| *known == word)
        .unwrap_or("a value")
}

/// The YAML parser's trailing ` at line L column C`, kept only when it is exactly
/// that, so no part of a value can ride along.
fn location(tail: &str) -> &str {
    let Some(at) = tail.rfind(" at line ") else {
        return "";
    };
    let suffix = &tail[at..];
    let mut words = suffix.split(' ').skip(1);
    let exact = matches!(
        (words.next(), words.next(), words.next(), words.next(), words.next()),
        (Some("at"), Some("line"), Some(line), Some("column"), Some(column))
            if line.bytes().all(|b| b.is_ascii_digit())
                && column.bytes().all(|b| b.is_ascii_digit())
                && !line.is_empty()
                && !column.is_empty()
    ) && words.next().is_none();
    if exact { suffix } else { "" }
}

/// Parse `text` into `T`. A key repeated in a struct or in a `Value` is
/// refused; a key repeated in a map keeps its last value.
pub(crate) fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    serde_yaml::from_str(text).map_err(Error)
}

/// Parse `text` as figment's `Dict`, the way the config loader reads it: a
/// repeated key keeps its last value at every level.
pub(crate) fn from_str_loose(text: &str) -> Result<Dict, Error> {
    Yaml::from_str(text).map_err(Error)
}

/// The config file's data as figment's YAML provider gives it: the
/// document under its profile, or the provider's own error.
#[allow(
    clippy::result_large_err,
    reason = "figment's own `Provider::data` signature, which the config loader returns"
)]
pub(crate) fn figment_data(text: &str) -> figment::Result<Map<figment::Profile, Dict>> {
    Yaml::string(text).data()
}

/// Write `value` as YAML.
pub(crate) fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    serde_yaml::to_string(value).map_err(Error)
}

/// Convert `value` to a YAML tree.
pub(crate) fn to_value<T: Serialize>(value: T) -> Result<Value, Error> {
    serde_yaml::to_value(value).map_err(Error)
}

/// Read `T` out of a YAML tree.
pub(crate) fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, Error> {
    serde_yaml::from_value(value).map_err(Error)
}

/// Convert a YAML tree value to a JSON value (MIK-8425).
///
/// Null, bool and string map to themselves. An integer stays a JSON integer
/// over the full `i64` and `u64` range. A finite float stays a JSON float
/// (`1.0` stays `1.0`, not `1`); a non-finite float maps to null. A sequence
/// maps element by element. A tagged node `!t v` maps to the one-entry object
/// `{"!t": v}`, keeping the tag (with its leading `!`) as the key. A mapping
/// maps entry by entry in document order, so a later key that stringifies the
/// same overwrites an earlier one: a string key is kept, a bool key becomes
/// `"true"` or `"false"`, an integer key becomes its decimal string, a finite
/// float key becomes `serde_json`'s float text (`1.0` to `"1.0"`, `1e3` to
/// `"1000.0"`, `-0.0` to `"-0.0"`), and any other key (null, non-finite
/// float, sequence, mapping, tagged) drops its entry.
///
/// MIG.2 re-implements this function over its own tree against the
/// parser/registry tests.
pub(crate) fn to_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_json::Value::Number(i.into())
            } else if let Some(u) = n.as_u64() {
                serde_json::Value::Number(u.into())
            } else {
                n.as_f64()
                    .and_then(serde_json::Number::from_f64)
                    .map_or(serde_json::Value::Null, serde_json::Value::Number)
            }
        }
        Value::String(s) => serde_json::Value::String(s.clone()),
        Value::Sequence(seq) => serde_json::Value::Array(seq.iter().map(to_json).collect()),
        Value::Tagged(tagged) => {
            let mut map = serde_json::Map::new();
            map.insert(tagged.tag.to_string(), to_json(&tagged.value));
            serde_json::Value::Object(map)
        }
        Value::Mapping(mapping) => {
            let mut map = serde_json::Map::new();
            for (key, val) in mapping {
                if let Some(key) = json_key(key) {
                    map.insert(key, to_json(val));
                }
            }
            serde_json::Value::Object(map)
        }
    }
}

/// Stringify a YAML mapping key for `to_json`; `None` drops the entry.
fn json_key(key: &Value) -> Option<String> {
    match key {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(i.to_string())
            } else if let Some(u) = n.as_u64() {
                Some(u.to_string())
            } else {
                let f = n.as_f64()?;
                serde_json::Number::from_f64(f).map(|j| j.to_string())
            }
        }
        _ => None,
    }
}

/// Every document of a multi-document stream, in order, ending after the
/// first refusal. `serde_yaml`'s own stream can keep yielding after a
/// malformed document, so a caller that does not stop grows without bound;
/// this iterator stops for it. There is no document count cap: a long
/// manifest is read in full.
pub(crate) fn documents(text: &str) -> impl Iterator<Item = Result<Value, Error>> + '_ {
    let mut stream = serde_yaml::Deserializer::from_str(text);
    let mut refused = false;
    std::iter::from_fn(move || {
        if refused {
            return None;
        }
        let document = stream.next()?;
        let reading = <Value as serde::Deserialize>::deserialize(document).map_err(Error);
        refused = reading.is_err();
        Some(reading)
    })
}
