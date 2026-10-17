// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway's one YAML seam (MIK-8425).
//!
//! Every YAML read and write goes through here, so the parser behind it can
//! be replaced in one place. Today the backend is serde_yaml 0.9.34, and
//! each item is that crate's own behaviour, unchanged: the tree types are
//! re-exported and the functions delegate. A later stage swaps the backend
//! behind this same surface; `tests/fixtures/mik_8425_yaml/` records what
//! it must reproduce.
//!
//! This file names nothing under `crate::`. Integration tests compile it
//! directly (`tests/common/yaml.rs`), so tests and the gateway always share
//! one implementation.
#![allow(
    dead_code,
    reason = "MIK-8425: consumers are routed through this seam in MIG.1b to MIG.1f; \
              until then parts of it have no caller"
)]

use figment::Provider as _;
use figment::providers::{Format as _, Yaml};
use figment::value::{Dict, Map};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// The YAML tree, its mapping and the parse error. They stay serde_yaml's
/// own until the backend swap, which keeps routing a pure path rename.
pub(crate) use serde_yaml::{Error, Mapping, Value};

/// Parse `text` into `T`. A key repeated in a struct or in a `Value` is
/// refused; a key repeated in a map keeps its last value.
pub(crate) fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    serde_yaml::from_str(text)
}

/// Parse `text` as figment's `Dict`, the way the config loader reads it: a
/// repeated key keeps its last value at every level.
pub(crate) fn from_str_loose(text: &str) -> Result<Dict, Error> {
    Yaml::from_str(text)
}

/// The config file's data as figment's YAML provider gives it: the
/// document under its profile, or the provider's own error.
pub(crate) fn figment_data(text: &str) -> figment::Result<Map<figment::Profile, Dict>> {
    Yaml::string(text).data()
}

/// Write `value` as YAML.
pub(crate) fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    serde_yaml::to_string(value)
}

/// Convert `value` to a YAML tree.
pub(crate) fn to_value<T: Serialize>(value: T) -> Result<Value, Error> {
    serde_yaml::to_value(value)
}

/// Read `T` out of a YAML tree.
pub(crate) fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, Error> {
    serde_yaml::from_value(value)
}

/// Every document of a multi-document stream, in order, ending after the
/// first refusal. serde_yaml's own stream can keep yielding after a
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
        let reading = <Value as serde::Deserialize>::deserialize(document);
        refused = reading.is_err();
        Some(reading)
    })
}
