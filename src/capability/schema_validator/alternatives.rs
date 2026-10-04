// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7818: `anyOf` / `oneOf` alternatives on an object schema: which
//! parameters must be given together or exclusively, and the schema a client
//! is shown once the gateway enforces them.

use serde_json::Value;

use super::ValidationViolation;
/// `anyOf` / `oneOf` on an object schema, each a list of alternatives that name
/// `required` parameters (and may pin one with `properties: {x: {const: v}}`).
/// `anyOf` needs at least one alternative satisfied, `oneOf` exactly one: a
/// parameter set the upstream cannot act on, or acts on ambiguously, is
/// refused here, before any request. Nothing else of JSON Schema's
/// combinators is read.
pub(super) fn alternatives_violations(
    schema: &Value,
    arguments: &serde_json::Map<String, Value>,
    violations: &mut Vec<ValidationViolation>,
) {
    for (keyword, exactly_one) in [("anyOf", false), ("oneOf", true)] {
        let Some(alternatives) = schema.get(keyword).and_then(Value::as_array) else {
            continue;
        };
        // A branch this reader does not understand (an enum, a type, a nested
        // combinator) would count as always satisfied and make a valid call
        // look ambiguous: leave such a list alone, as before it was read.
        if !alternatives.iter().all(alternative_is_supported) {
            continue;
        }
        let satisfied = alternatives
            .iter()
            .filter(|alternative| alternative_holds(alternative, arguments))
            .count();
        if satisfied >= 1 && (!exactly_one || satisfied == 1) {
            continue;
        }
        let names: Vec<&str> = alternatives
            .iter()
            .filter_map(|alternative| alternative.get("required")?.as_array())
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let rule = if exactly_one {
            "exactly one of"
        } else {
            "at least one of"
        };
        violations.push(ValidationViolation::new(
            names.join(", "),
            format!("provide {rule}: {}", names.join(", ")),
        ));
    }
}

/// The shapes [`alternative_holds`] reads: `required`, and `properties` whose
/// entries only pin a `const`; titles and descriptions are ignored.
fn alternative_is_supported(alternative: &Value) -> bool {
    let Some(object) = alternative.as_object() else {
        return false;
    };
    object.iter().all(|(key, value)| match key.as_str() {
        "required" | "title" | "description" => true,
        "properties" => value.as_object().is_some_and(|properties| {
            properties.values().all(|property| {
                property.as_object().is_some_and(|keys| {
                    keys.keys()
                        .all(|k| matches!(k.as_str(), "const" | "title" | "description"))
                })
            })
        }),
        _ => false,
    })
}

/// The input schema a client is shown: without a root `anyOf` or `oneOf` that
/// `alternatives_violations` enforces. Some clients refuse a whole request when
/// a tool's schema has one there; the gateway still enforces these on every
/// call, and the capability's description says what is required. A combinator
/// the gateway does not enforce (`allOf`, or a list with a branch it does not
/// read) stays listed, so hiding it never drops a constraint from both sides.
#[must_use]
pub(crate) fn advertised_input_schema(schema: &Value) -> Value {
    let mut shown = schema.clone();
    if let Some(object) = shown.as_object_mut()
        // `validate_object` reads nothing, alternatives included, without
        // root `properties`; so nothing is enforced and nothing may be hidden.
        && object.get("properties").is_some_and(Value::is_object)
    {
        for keyword in ["anyOf", "oneOf"] {
            let enforced = object
                .get(keyword)
                .and_then(Value::as_array)
                .is_some_and(|alternatives| alternatives.iter().all(alternative_is_supported));
            if enforced {
                object.remove(keyword);
            }
        }
    }
    shown
}

/// An alternative holds when every `required` parameter is present and not
/// null, and every `const`-pinned parameter that is present has that value.
fn alternative_holds(alternative: &Value, arguments: &serde_json::Map<String, Value>) -> bool {
    let present = |name: &str| arguments.get(name).is_some_and(|value| !value.is_null());
    let required_ok = alternative
        .get("required")
        .and_then(Value::as_array)
        .is_none_or(|names| names.iter().filter_map(Value::as_str).all(present));
    let pinned_ok = alternative
        .get("properties")
        .and_then(Value::as_object)
        .is_none_or(|properties| {
            properties.iter().all(|(name, property)| {
                match (arguments.get(name), property.get("const")) {
                    (Some(value), Some(pinned)) => value == pinned,
                    _ => true,
                }
            })
        });
    required_ok && pinned_ok
}
