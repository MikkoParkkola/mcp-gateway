// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Resolution bound for a tool schema the gateway is about to publish.
//!
//! MIK-6865.SCHEMA.1c, reading (c): every `$ref` in a published schema must
//! resolve to a target that exists in the SAME document. Meta-validation cannot
//! answer this — a schema pointing at a `$defs` entry nobody wrote is
//! structurally well-formed and validates cleanly — and resolution is the
//! question a client actually hits.
//!
//! STATED LIMIT: this bounds `$ref` resolution and nothing else. 2020-12
//! meta-validity of the schema document is NOT checked here, because checking it
//! would put a validator on the trust path of every emitted descriptor — a
//! runtime dependency the release team lead declined on 2026-09-08 (ruling R6,
//! `docs/release/2026-09-08-team-lead-rulings.md`). First-party schemas are
//! meta-validated in `tests/schema_2020_12_validity.rs`; forwarded ones are not.
//!
//! Composition (`allOf`/`anyOf`/`oneOf`/`not`/`if`) is legal 2020-12 and is not
//! a bound under reading (c). It is observed in tests, never constrained here.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Verdict recorded beside a published schema. Additive: the schema itself is
/// judged, never altered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum SchemaBounds {
    /// Every local `$ref` resolves within the document.
    Within,
    /// At least one `$ref` does not resolve; each such pointer is named.
    #[serde(rename_all = "camelCase")]
    OutOfBounds {
        /// The pointers that do not resolve, in document order.
        unresolved_refs: Vec<String>,
    },
}

impl SchemaBounds {
    /// Inspect one schema document and record the verdict.
    ///
    /// ```
    /// use mcp_gateway::trust::SchemaBounds;
    ///
    /// let resolves = serde_json::json!({
    ///     "$defs": { "Target": { "type": "string" } },
    ///     "properties": { "target": { "$ref": "#/$defs/Target" } }
    /// });
    /// assert_eq!(SchemaBounds::inspect(&resolves), SchemaBounds::Within);
    ///
    /// let dangles = serde_json::json!({ "$ref": "#/$defs/Absent" });
    /// assert_eq!(
    ///     SchemaBounds::inspect(&dangles),
    ///     SchemaBounds::OutOfBounds { unresolved_refs: vec!["#/$defs/Absent".to_string()] }
    /// );
    /// ```
    #[must_use]
    pub fn inspect(schema: &Value) -> Self {
        let unresolved_refs = unresolved_refs(schema);
        if unresolved_refs.is_empty() {
            Self::Within
        } else {
            Self::OutOfBounds { unresolved_refs }
        }
    }
}

/// Return every `$ref` in `schema` that does not resolve inside `schema`.
///
/// One walker decides for both the emit path and the observing tests, so a
/// schema the tests call bounded cannot be a schema the gateway publishes
/// unbounded.
#[must_use]
pub fn unresolved_refs(schema: &Value) -> Vec<String> {
    let mut found = Vec::new();
    walk(schema, schema, &mut found);
    found
}

/// Resolve one `$ref` against the document root.
///
/// Only local pointers can resolve in-document. An external `$ref` is a fetch
/// this gateway must never make (the `jsonschema` dependency is built
/// `default-features = false` precisely to disable remote resolution), so it
/// cannot resolve here and is reported.
///
/// ponytail: JSON-pointer fragments only. A plain-name fragment (`#name`,
/// resolved against `$anchor`) and an `$id`-relative base are both legal 2020-12
/// and are reported here as unresolved. Teach it `$anchor` and `$id` bases the
/// day a schema uses one, rather than editing schemas to suit the check.
fn resolves(root: &Value, pointer: &str) -> bool {
    let Some(rest) = pointer.strip_prefix('#') else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    let Some(path) = rest.strip_prefix('/') else {
        return false;
    };
    let mut node = root;
    for raw in path.split('/') {
        // RFC 6901 escaping: `~1` is `/` and `~0` is `~`, in that order.
        let token = raw.replace("~1", "/").replace("~0", "~");
        node = match node {
            Value::Object(map) => match map.get(&token) {
                Some(child) => child,
                None => return false,
            },
            Value::Array(items) => match token.parse::<usize>() {
                Ok(index) if index < items.len() => &items[index],
                _ => return false,
            },
            _ => return false,
        };
    }
    true
}

/// Depth-first walk collecting unresolvable `$ref` pointers in document order.
fn walk(root: &Value, node: &Value, found: &mut Vec<String>) {
    match node {
        Value::Object(map) => {
            if let Some(Value::String(pointer)) = map.get("$ref")
                && !resolves(root, pointer)
            {
                found.push(pointer.clone());
            }
            for child in map.values() {
                walk(root, child, found);
            }
        }
        Value::Array(items) => {
            for child in items {
                walk(root, child, found);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_schema_with_no_refs_at_all_is_within_bounds() {
        // GIVEN a schema that never points anywhere
        let schema = json!({ "type": "object", "properties": { "q": { "type": "string" } } });

        // WHEN inspected
        // THEN nothing is unresolvable
        assert_eq!(SchemaBounds::inspect(&schema), SchemaBounds::Within);
    }

    #[test]
    fn a_ref_inside_an_array_branch_is_reached_by_the_walk() {
        // GIVEN a dangling pointer buried in a composition array
        let schema = json!({ "allOf": [{ "$ref": "#/$defs/Absent" }] });

        // WHEN inspected
        // THEN the array branch is walked, not skipped
        assert_eq!(
            SchemaBounds::inspect(&schema),
            SchemaBounds::OutOfBounds {
                unresolved_refs: vec!["#/$defs/Absent".to_string()]
            }
        );
    }

    #[test]
    fn an_external_ref_cannot_resolve_and_is_reported() {
        // GIVEN a pointer at another document
        let schema = json!({ "$ref": "https://example.test/schema.json" });

        // WHEN inspected
        // THEN it is out of bounds — this gateway never fetches it
        assert_eq!(
            SchemaBounds::inspect(&schema),
            SchemaBounds::OutOfBounds {
                unresolved_refs: vec!["https://example.test/schema.json".to_string()]
            }
        );
    }

    #[test]
    fn an_escaped_pointer_token_resolves_through_rfc_6901_unescaping() {
        // GIVEN a `$defs` key containing a literal slash
        let schema = json!({
            "$defs": { "a/b": { "type": "string" } },
            "$ref": "#/$defs/a~1b"
        });

        // WHEN inspected
        // THEN `~1` is read as `/` and the pointer resolves
        assert_eq!(SchemaBounds::inspect(&schema), SchemaBounds::Within);
    }

    #[test]
    fn an_index_past_the_end_of_an_array_does_not_resolve() {
        // GIVEN a pointer into an array slot that does not exist
        let schema = json!({ "$defs": [ { "type": "string" } ], "$ref": "#/$defs/1" });

        // WHEN inspected
        // THEN the out-of-range index is reported, not silently accepted
        assert_eq!(
            SchemaBounds::inspect(&schema),
            SchemaBounds::OutOfBounds {
                unresolved_refs: vec!["#/$defs/1".to_string()]
            }
        );
    }

    #[test]
    fn the_empty_fragment_resolves_to_the_document_root() {
        // GIVEN a self-reference
        let schema = json!({ "properties": { "self": { "$ref": "#" } } });

        // WHEN inspected
        // THEN `#` is the root and resolves
        assert_eq!(SchemaBounds::inspect(&schema), SchemaBounds::Within);
    }

    #[test]
    fn the_within_verdict_serializes_without_a_pointer_list() {
        // GIVEN the bounded verdict
        // WHEN serialized
        // THEN it carries a status and nothing else
        assert_eq!(
            serde_json::to_value(SchemaBounds::Within).expect("verdict must serialize"),
            json!({ "status": "within" })
        );
    }

    #[test]
    fn the_out_of_bounds_verdict_serializes_with_camel_case_pointers() {
        // GIVEN the unbounded verdict
        let verdict = SchemaBounds::OutOfBounds {
            unresolved_refs: vec!["#/$defs/Absent".to_string()],
        };

        // WHEN serialized
        // THEN the wire shape is the one the descriptor publishes
        assert_eq!(
            serde_json::to_value(verdict).expect("verdict must serialize"),
            json!({ "status": "outOfBounds", "unresolvedRefs": ["#/$defs/Absent"] })
        );
    }
}
