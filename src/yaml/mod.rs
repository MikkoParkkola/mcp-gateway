// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway's one YAML seam (MIK-8425).
//!
//! Every YAML read and write goes through here. Since MIG.2 the backend is
//! the adapter's own (`next/`): granit-parser's events read into a parse
//! representation, a serde `Deserializer` and `Serializer` with the replaced
//! backend's rules, and a writer byte-equal to its output.
//! `tests/fixtures/mik_8425_yaml/` records what every function must
//! reproduce, and `tests/mik_8425_mig2_parity.rs` holds the backend to it.
//! One function is the seam's own: `to_json`, the tree-to-JSON conversion
//! that `ImportedSkill.extra` uses, pinned by the skills parser and
//! registry tests. The seam's own `Error` (every function here except
//! `figment_data`) never prints the value that caused it (MIK-8425 B3);
//! `figment_data` returns figment's error, which `config/load_error.rs`
//! (`from_figment`) redacts.
//!
//! These files name nothing under `crate::`. Integration tests compile it
//! directly (`tests/common/yaml.rs`), so tests and the gateway always share
//! one implementation.
#![allow(
    dead_code,
    unused_imports,
    reason = "integration-test crates compile their own copy through tests/common/yaml.rs \
              and never call all of it, and the tree keeps the replaced backend's whole \
              accessor surface, which the gateway does not use in full"
)]

mod error;
mod guard;
pub(crate) mod next;

pub(crate) use error::{Error, Limit, Location, redact_message};
use guard::guard;
#[cfg(test)]
pub(crate) use guard::guard_work;
pub(crate) use next::{Mapping, Value, figment_data, from_str_loose};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Parse `text` into `T`. A key repeated in a struct or in a `Value` is
/// refused; a key repeated in a map keeps its last value.
pub(crate) fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    next::from_str(text)
}

/// Write `value` as YAML.
pub(crate) fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    next::to_string(value)
}

/// Convert `value` to a YAML tree.
pub(crate) fn to_value<T: Serialize>(value: T) -> Result<Value, Error> {
    next::to_value(value)
}

/// Read `T` out of a YAML tree.
pub(crate) fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, Error> {
    next::from_value(value)
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

/// Every document of a multi-document stream, in order, an empty one as
/// null, ending after the first refusal. There is no document count cap: a
/// long manifest is read in full.
pub(crate) fn documents(text: &str) -> impl Iterator<Item = Result<Value, Error>> + '_ {
    next::documents(text)
}
