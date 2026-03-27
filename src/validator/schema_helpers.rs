//! JSON Schema navigation helpers shared between the agent-UX validator and
//! the capability structural validator.
//!
//! Both validator domains operate on raw `serde_json::Value` JSON Schema
//! objects.  These helpers centralise the small navigational idioms so that
//! the property-extraction and required-array patterns cannot drift between
//! the two sites.

use std::collections::HashSet;

use serde_json::{Map, Value};

/// Return the `properties` map of a JSON Schema object, if present and valid.
///
/// Returns `None` when the schema has no `properties` key or its value is not
/// a JSON object (e.g. an array).
pub(crate) fn input_properties(schema: &Value) -> Option<&Map<String, Value>> {
    schema.get("properties").and_then(|p| p.as_object())
}

/// Collect all top-level property names from a JSON Schema input object.
///
/// Returns an empty set when `schema.properties` is absent or is not a JSON
/// object.
pub(crate) fn input_property_names(schema: &Value) -> HashSet<String> {
    input_properties(schema)
        .map(|props| props.keys().cloned().collect())
        .unwrap_or_default()
}

/// Return `true` if the JSON Schema has a non-empty `required` array.
pub(crate) fn has_required_array(schema: &Value) -> bool {
    schema
        .get("required")
        .is_some_and(|r| r.as_array().is_some_and(|a| !a.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── input_properties ──────────────────────────────────────────────────────

    #[test]
    fn input_properties_returns_map_when_present() {
        let schema = json!({
            "type": "object",
            "properties": {
                "query": { "type": "string" }
            }
        });
        let props = input_properties(&schema).expect("should have properties");
        assert!(props.contains_key("query"));
    }

    #[test]
    fn input_properties_returns_none_when_absent() {
        assert!(input_properties(&json!({ "type": "object" })).is_none());
    }

    #[test]
    fn input_properties_returns_none_when_properties_is_array() {
        // Malformed schema – properties is a list instead of an object.
        assert!(input_properties(&json!({ "properties": ["a", "b"] })).is_none());
    }

    // ── input_property_names ──────────────────────────────────────────────────

    #[test]
    fn input_property_names_collects_all_keys() {
        let schema = json!({
            "properties": {
                "alpha": { "type": "string" },
                "beta":  { "type": "integer" }
            }
        });
        let names = input_property_names(&schema);
        assert_eq!(names.len(), 2);
        assert!(names.contains("alpha"));
        assert!(names.contains("beta"));
    }

    #[test]
    fn input_property_names_empty_when_no_properties() {
        assert!(input_property_names(&json!({})).is_empty());
    }

    #[test]
    fn input_property_names_empty_when_properties_is_array() {
        assert!(input_property_names(&json!({ "properties": [] })).is_empty());
    }

    // ── has_required_array ────────────────────────────────────────────────────

    #[test]
    fn has_required_array_true_when_present_and_nonempty() {
        assert!(has_required_array(&json!({ "required": ["id"] })));
    }

    #[test]
    fn has_required_array_false_when_absent() {
        assert!(!has_required_array(&json!({ "type": "object" })));
    }

    #[test]
    fn has_required_array_false_when_empty_array() {
        assert!(!has_required_array(&json!({ "required": [] })));
    }

    #[test]
    fn has_required_array_false_when_required_is_not_array() {
        assert!(!has_required_array(&json!({ "required": "id" })));
    }
}
