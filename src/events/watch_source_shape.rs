// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A subscription's watch options, and the part of an answer its digest
//! covers.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{Map, Value, json};

use super::super::types::RpcError;
use super::{DEFAULT_INTERVAL, MAX_INTERVAL, MIN_INTERVAL, VOLATILE};

/// A subscription's watch options, validated.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Options {
    pub(super) arguments: Value,
    pub(super) interval: Duration,
    pub(super) fields: Option<Vec<String>>,
}

pub(super) fn options(arguments: &Value) -> Result<Options, RpcError> {
    let call = match arguments.get("arguments") {
        None => json!({}),
        Some(object @ Value::Object(_)) => object.clone(),
        Some(_) => return Err(RpcError::invalid("arguments.arguments")),
    };
    let interval = match arguments.get("interval") {
        None => DEFAULT_INTERVAL,
        Some(value) => value
            .as_u64()
            .filter(|s| (MIN_INTERVAL..=MAX_INTERVAL).contains(s))
            .ok_or_else(|| RpcError::invalid("arguments.interval"))?,
    };
    let fields = match arguments.get("fields") {
        None => None,
        Some(Value::Array(items)) if !items.is_empty() => Some(
            items
                .iter()
                .map(|p| p.as_str().filter(|p| p.starts_with('/')).map(str::to_owned))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| RpcError::invalid("arguments.fields"))?,
        ),
        Some(_) => return Err(RpcError::invalid("arguments.fields")),
    };
    Ok(Options {
        arguments: call,
        interval: Duration::from_secs(interval),
        fields,
    })
}

/// The part of an answer the digest covers, as pointer -> value: the named
/// `fields`, or every top-level key but `_meta` and the volatile ones.
pub(super) fn projection(value: &Value, fields: Option<&[String]>) -> BTreeMap<String, Value> {
    match fields {
        Some(pointers) => pointers
            .iter()
            .filter_map(|p| value.pointer(p).map(|v| (p.clone(), v.clone())))
            .collect(),
        None => match value {
            Value::Object(map) => map
                .iter()
                .filter(|(k, _)| k.as_str() != "_meta" && !VOLATILE.contains(&k.as_str()))
                .map(|(k, v)| {
                    (
                        format!("/{}", k.replace('~', "~0").replace('/', "~1")),
                        v.clone(),
                    )
                })
                .collect(),
            other => BTreeMap::from([(String::new(), other.clone())]),
        },
    }
}

/// SHA-256 over the JCS of a projection, `sha256:` + hex.
pub(super) fn digest(projection: &BTreeMap<String, Value>) -> String {
    use sha2::Digest as _;
    let map: Map<String, Value> = projection.clone().into_iter().collect();
    let bytes = serde_json::to_vec(&Value::Object(map)).unwrap_or_default();
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

/// The pointers whose values differ between two projections.
pub(super) fn changed(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
) -> Vec<String> {
    let mut keys: Vec<&String> = before.keys().chain(after.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter(|k| before.get(*k) != after.get(*k))
        .cloned()
        .collect()
}
