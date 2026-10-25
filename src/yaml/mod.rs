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
//! These files name nothing under `crate::`. Integration tests compile it
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

mod error;
mod guard;
pub(crate) mod next;
mod provider;

pub(crate) use error::{Error, Limit, Location, redact_message};
use guard::guard;
#[cfg(test)]
pub(crate) use guard::guard_work;
pub(crate) use provider::{figment_data, from_str_loose};

use figment::Provider as _;
use figment::providers::{Format as _, Yaml};
use figment::value::{Dict, Map};
use granit_parser::{ErrorKind, Event, Marker, ScanError, Tag, TokenType};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::{HashMap, HashSet};

/// The YAML tree and its mapping. They stay `serde_yaml`'s own until the
/// backend swap, which keeps routing a pure path rename.
pub(crate) use serde_yaml::{Mapping, Value};

/// Parse `text` into `T`. A key repeated in a struct or in a `Value` is
/// refused; a key repeated in a map keeps its last value.
pub(crate) fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    guard(text)?;
    serde_yaml::from_str(text).map_err(Error::backend)
}

/// Write `value` as YAML.
pub(crate) fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    serde_yaml::to_string(value).map_err(Error::backend)
}

/// Convert `value` to a YAML tree.
pub(crate) fn to_value<T: Serialize>(value: T) -> Result<Value, Error> {
    serde_yaml::to_value(value).map_err(Error::backend)
}

/// Read `T` out of a YAML tree.
pub(crate) fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, Error> {
    serde_yaml::from_value(value).map_err(Error::backend)
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
    let mut early = guard(text).err();
    let mut stream = serde_yaml::Deserializer::from_str(text);
    let mut refused = early.is_some();
    std::iter::from_fn(move || {
        if let Some(err) = early.take() {
            return Some(Err(err));
        }
        if refused {
            return None;
        }
        let document = stream.next()?;
        let reading = <Value as serde::Deserialize>::deserialize(document).map_err(Error::backend);
        refused = reading.is_err();
        Some(reading)
    })
}
