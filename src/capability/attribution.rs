// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The credit a capability's provider licence requires, set on every
//! successful result at both exits (the backend's and `gateway_invoke`'s).

use serde_json::{Value, json};

use super::CapabilityDefinition;

/// `result` with the attribution `capability` declares: an object gains its
/// `attribution` key (a provider field of that name is overwritten), and any
/// other value is wrapped as `{"results": <value>, "attribution": <text>}`.
/// Applying it to its own output changes nothing, so the two exits never
/// nest or wrap twice. A capability that declares none is untouched.
pub(crate) fn apply_attribution(capability: &CapabilityDefinition, result: Value) -> Value {
    let Some(text) = capability.attribution.as_deref() else {
        return result;
    };
    match result {
        Value::Object(mut map) => {
            map.insert("attribution".to_owned(), Value::from(text));
            Value::Object(map)
        }
        other => json!({ "results": other, "attribution": text }),
    }
}
