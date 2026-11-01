// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway's one YAML seam (MIK-8425).
//!
//! Every YAML read and write goes through here. Since MIG.2 the backend is
//! the adapter's own: granit-parser's events read into a parse
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

mod de;
mod emit;
mod error;
mod guard;
mod mapping;
mod nodes;
mod number;
mod rep;
mod resolve;
mod ser;
mod spans;
mod tagged;
mod value;
mod value_de;

/// Any string as one valid double-quoted YAML scalar.
pub(crate) use emit::quote_double as double_quoted;
pub(crate) use error::{Error, Limit, Location, redact_message};
pub(crate) use guard::MAX_YAML_BYTES;
use guard::guard;
#[cfg(test)]
pub(crate) use guard::guard_work;
pub(crate) use mapping::Mapping;
pub(crate) use nodes::{Node, Shape, Step, block_nodes};
pub(crate) use number::Number;
pub(crate) use spans::{ValueSpan, mapping_values};
pub(crate) use tagged::{Tag, TaggedValue};
pub(crate) use value::{Sequence, Value};

use figment::value::{Dict, Map};
use serde::Serialize;
use serde::de::DeserializeOwned;

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

/// The replaced backend's refusal of a second document where one is read.
const MORE_THAN_ONE: &str =
    "deserializing from YAML containing more than one document is not supported";

/// `T` from the only document in `text`. The first document is read before
/// a second one is refused, so its own error wins, as before.
pub(crate) fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    guard(text)?;
    let documents = rep::parse(text)?;
    let value = de::from_document(&documents[0])?;
    if documents.len() > 1 {
        return Err(Error::message(MORE_THAN_ONE));
    }
    Ok(value)
}

/// figment's `Dict` from `text`: a repeated key keeps its last value, at
/// every level (D4).
pub(crate) fn from_str_loose(text: &str) -> Result<Dict, Error> {
    from_str(text)
}

#[allow(
    clippy::result_large_err,
    reason = "figment's own `Provider::data` signature, which the config loader returns"
)]
pub(crate) fn figment_data(text: &str) -> figment::Result<Map<figment::Profile, Dict>> {
    let dict = from_str_loose(text).map_err(|err| figment::Error::from(err.to_string()))?;
    Ok(figment::Profile::Default.collect(dict))
}

/// `value` as YAML text, byte-equal to the replaced backend's output (D20).
pub(crate) fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    emit::emit(&ser::to_text_tree(value)?)
}

/// `value` as a tree: unit variants as their names, other variants under
/// their `!variant` tag (D5).
pub(crate) fn to_value<T: Serialize>(value: T) -> Result<Value, Error> {
    ser::to_value(&value)
}

/// `T` from a tree the caller already has.
pub(crate) fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, Error> {
    T::deserialize(value)
}

/// Every document in `text` as a tree, an empty one as null, ending at the
/// first refusal (D19). The guard refuses the stream as a whole.
pub(crate) fn documents(text: &str) -> impl Iterator<Item = Result<Value, Error>> + '_ {
    let parsed = guard(text).and_then(|()| rep::parse(text));
    let readings: Vec<Result<Value, Error>> = match parsed {
        Err(error) => vec![Err(error)],
        Ok(documents) => {
            let mut out = Vec::with_capacity(documents.len());
            for document in &documents {
                let reading = de::from_document(document);
                let refused = reading.is_err();
                out.push(reading);
                if refused {
                    break;
                }
            }
            out
        }
    };
    readings.into_iter()
}
