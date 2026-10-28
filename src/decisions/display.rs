// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What an item may show of text that came from a note or a changed file.
//!
//! A name is shown only if it passes the backend-name character rule;
//! otherwise, and for every name read from changed capability bytes, it is a
//! keyed label. An issuer is shown as its host, an agent URI as scheme and
//! host. A changed capability's summary carries counts and mapped types only.

use serde_json::{Value, json};

/// `name` if it passes the backend-name rule, else its keyed label.
pub(super) fn name(key: &[u8; 32], name: &str) -> String {
    if crate::config::backend_add::validate_backend_name(name).is_ok() {
        name.to_string()
    } else {
        label(key, name)
    }
}

/// A stable stand-in that shows nothing of `text`.
pub(super) fn label(key: &[u8; 32], text: &str) -> String {
    let digest = crate::hashing::hmac_sha256_hex(key, text.as_bytes());
    format!("unnamed-{}", &digest[..8])
}

/// An issuer authority as its host, or a checked name when it is no URL.
pub(super) fn authority(key: &[u8; 32], authority: &str) -> String {
    url::Url::parse(authority)
        .ok()
        .and_then(|url| url.host_str().map(|host| name(key, host)))
        .unwrap_or_else(|| name(key, authority))
}

/// A `source:id` agent with its id as scheme and host when it is a URI.
pub(super) fn agent(key: &[u8; 32], agent: &str) -> String {
    let Some((source, id)) = agent.split_once(':') else {
        return name(key, agent);
    };
    // A URL scheme is letters, digits, `+`, `-` and `.` only, so it is shown.
    let url = url::Url::parse(id).ok();
    let shown = match url
        .as_ref()
        .and_then(|url| Some((url.scheme(), url.host_str()?)))
    {
        Some((scheme, host)) => format!("{scheme}://{}", name(key, host)),
        None => name(key, id),
    };
    format!("{}:{shown}", name(key, source))
}

/// A schema type mapped onto the closed set the list may show.
fn mapped_type(value: Option<&Value>) -> &'static str {
    match value.and_then(Value::as_str) {
        Some("string") => "string",
        Some("number") => "number",
        Some("integer") => "integer",
        Some("boolean") => "boolean",
        Some("object") => "object",
        Some("array") => "array",
        Some("null") => "null",
        _ => "other",
    }
}

/// The structure of a changed capability's input: counts, mapped types and
/// its hints. No name, description, default, example, constant or pattern.
pub(super) fn summary(content: &str) -> Value {
    let parsed: Value = crate::yaml::from_str(content).unwrap_or(Value::Null);
    let input = parsed.pointer("/schema/input");
    let properties = input
        .and_then(|input| input.get("properties"))
        .and_then(Value::as_object);
    let mut types: Vec<&str> = properties
        .map(|props| {
            props
                .values()
                .map(|prop| mapped_type(prop.get("type")))
                .collect()
        })
        .unwrap_or_default();
    types.sort_unstable();
    let required = input
        .and_then(|input| input.get("required"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let hint = |path: &str| parsed.pointer(path).and_then(Value::as_bool);
    json!({
        "parsed": !parsed.is_null(),
        "property_count": types.len(),
        "property_types": types,
        "required_count": required,
        "read_only": hint("/metadata/read_only"),
        "destructive": hint("/metadata/destructive"),
    })
}
