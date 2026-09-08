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
//!
//! POPULATION: this closes the DESCRIPTOR surface — every `tools/list` route
//! crosses `project_tool_descriptor_trust_card`. Two client-visible schema
//! exits are not descriptors and carry no verdict: `gateway_search` at its full
//! disclosure tier copies a backend `input_schema` into a search result
//! (`src/gateway/search_disclosure.rs`), and a backend entry the proxy cannot
//! deserialize into a `Tool` is forwarded verbatim rather than dropped
//! (`src/gateway/router/backend_handlers.rs`). Both are inspectable by this same
//! walker the day that surface is decided to need a verdict.

use std::borrow::Cow;

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

    /// Inspect BOTH schema documents a descriptor can publish.
    ///
    /// A `$ref` resolves inside its OWN document, so the two are walked
    /// separately. An output-schema pointer is reported qualified
    /// (`outputSchema#/$defs/X`) — the bare fragment would be indistinguishable
    /// from an input-schema one, and a client cannot act on an ambiguous
    /// pointer.
    #[must_use]
    pub fn inspect_descriptor(input: &Value, output: Option<&Value>) -> Self {
        let mut unresolved_refs = unresolved_refs(input);
        if let Some(output) = output {
            unresolved_refs.extend(
                self::unresolved_refs(output)
                    .into_iter()
                    .map(|pointer| format!("outputSchema{pointer}")),
            );
        }
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

/// Resolve one `$ref` against the root of its own resource.
///
/// `root` is the nearest enclosing `$id`, not necessarily the whole document —
/// see `walk`.
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
    let Some(decoded) = percent_decode(rest) else {
        return false;
    };
    if decoded.is_empty() {
        return true;
    }
    let Some(path) = decoded.strip_prefix('/') else {
        return false;
    };
    let mut node = root;
    for raw in path.split('/') {
        let Some(token) = unescape(raw) else {
            return false;
        };
        node = match node {
            Value::Object(map) => match map.get(token.as_ref()) {
                Some(child) => child,
                None => return false,
            },
            Value::Array(items) => match array_index(&token) {
                Some(index) if index < items.len() => &items[index],
                _ => return false,
            },
            _ => return false,
        };
    }
    true
}

/// Percent-decode a URI fragment, per RFC 6901 §6.
///
/// A malformed escape makes the pointer unusable, not lenient: `None` is
/// reported as unresolved rather than matched as literal text.
fn percent_decode(fragment: &str) -> Option<Cow<'_, str>> {
    if !fragment.contains('%') {
        return Some(Cow::Borrowed(fragment));
    }
    let bytes = fragment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok().map(Cow::Owned)
}

/// Unescape one reference token: `~1` is `/`, `~0` is `~` (RFC 6901 §3).
///
/// A `~` followed by anything else is NOT a token — the whole pointer is
/// malformed, so the ref is reported rather than matched literally.
fn unescape(token: &str) -> Option<Cow<'_, str>> {
    if !token.contains('~') {
        return Some(Cow::Borrowed(token));
    }
    let mut out = String::with_capacity(token.len());
    let mut chars = token.chars();
    while let Some(c) = chars.next() {
        if c != '~' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('0') => out.push('~'),
            Some('1') => out.push('/'),
            _ => return None,
        }
    }
    Some(Cow::Owned(out))
}

/// Parse an array index under the RFC 6901 §4 grammar: `0` or `[1-9][0-9]*`.
///
/// `str::parse` is wider than the grammar — it accepts `00`, `+0` and unicode
/// digits, each of which would silently resolve a pointer no conforming
/// implementation resolves.
fn array_index(token: &str) -> Option<usize> {
    if token.is_empty() || (token != "0" && token.starts_with('0')) {
        return None;
    }
    if !token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    token.parse().ok()
}

/// Keywords whose value is a schema, or a legacy array of schemas (`items`).
const SCHEMA_VALUED: &[&str] = &[
    "additionalProperties",
    "allOf",
    "anyOf",
    "contains",
    "contentSchema",
    "else",
    "if",
    "items",
    "not",
    "oneOf",
    "prefixItems",
    "propertyNames",
    "then",
    "unevaluatedItems",
    "unevaluatedProperties",
];

/// Keywords whose value maps a name to a schema.
const SCHEMA_MAPPED: &[&str] = &[
    "$defs",
    "definitions",
    "dependentSchemas",
    "patternProperties",
    "properties",
];

/// Depth-first walk collecting unresolvable `$ref` pointers in document order.
///
/// Only SCHEMA-BEARING keyword locations are descended. A `$ref` key sitting
/// inside a `const`, `enum`, `default` or `examples` VALUE is ordinary data that
/// happens to spell a keyword, and reporting it would be a false alarm on a
/// schema that is perfectly bounded.
///
/// `$id` starts a new resource: a fragment inside an embedded resource resolves
/// against THAT resource, never the outer document. Without this a `#/$defs/x`
/// the embedded resource does not define reads as resolved because the outer
/// document happens to define it — a false `within`, the one direction of error
/// that matters.
fn walk(root: &Value, node: &Value, found: &mut Vec<String>) {
    let Value::Object(map) = node else {
        return;
    };
    let root = match map.get("$id") {
        Some(Value::String(_)) => node,
        _ => root,
    };
    if let Some(Value::String(pointer)) = map.get("$ref")
        && !resolves(root, pointer)
    {
        found.push(pointer.clone());
    }
    for child in SCHEMA_VALUED.iter().filter_map(|key| map.get(*key)) {
        match child {
            Value::Array(items) => items.iter().for_each(|item| walk(root, item, found)),
            other => walk(root, other, found),
        }
    }
    for key in SCHEMA_MAPPED {
        if let Some(Value::Object(children)) = map.get(*key) {
            children.values().for_each(|child| walk(root, child, found));
        }
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

    #[test]
    fn a_percent_encoded_fragment_names_the_decoded_token() {
        // GIVEN a target whose name contains a space, pointed at per RFC 6901 §6
        let schema = json!({
            "$defs": { "a b": { "type": "string" } },
            "properties": { "p": { "$ref": "#/$defs/a%20b" } }
        });

        // WHEN inspected
        // THEN the fragment is percent-decoded before it is split into tokens
        assert_eq!(SchemaBounds::inspect(&schema), SchemaBounds::Within);
    }

    #[test]
    fn a_malformed_escape_does_not_resolve() {
        // GIVEN a pointer whose `~` is followed by neither `0` nor `1`
        let schema = json!({
            "$defs": { "a~2b": {} },
            "properties": { "p": { "$ref": "#/$defs/a~2b" } }
        });

        // WHEN inspected
        // THEN the token is rejected as malformed rather than matched literally
        assert_eq!(
            SchemaBounds::inspect(&schema),
            SchemaBounds::OutOfBounds {
                unresolved_refs: vec!["#/$defs/a~2b".to_string()]
            }
        );
    }

    #[test]
    fn an_array_index_outside_the_rfc_6901_grammar_does_not_resolve() {
        // GIVEN pointers using `00` and `+0`, neither of which is a legal index
        let schema = json!({
            "prefixItems": [{ "type": "string" }],
            "$defs": {
                "a": { "$ref": "#/prefixItems/00" },
                "b": { "$ref": "#/prefixItems/+0" }
            }
        });

        // WHEN inspected
        // THEN both are reported, not silently parsed as index zero
        assert_eq!(
            SchemaBounds::inspect(&schema),
            SchemaBounds::OutOfBounds {
                unresolved_refs: vec![
                    "#/prefixItems/00".to_string(),
                    "#/prefixItems/+0".to_string()
                ]
            }
        );
    }

    #[test]
    fn a_literal_ref_key_inside_a_const_is_not_a_reference() {
        // GIVEN a schema whose `const`, `enum` and `default` values happen to
        // contain the string key `$ref` as ordinary data
        let schema = json!({
            "properties": {
                "p": {
                    "const": { "$ref": "#/$defs/Absent" },
                    "default": { "$ref": "#/$defs/AlsoAbsent" }
                },
                "q": { "enum": [{ "$ref": "#/$defs/StillAbsent" }] }
            }
        });

        // WHEN inspected
        // THEN the walk visits schema-bearing keywords only, so none is a $ref
        assert_eq!(SchemaBounds::inspect(&schema), SchemaBounds::Within);
    }

    #[test]
    fn a_fragment_inside_a_nested_id_resolves_against_that_resource() {
        // GIVEN an embedded resource that does NOT define the target its inner
        // `$ref` names, while the OUTER document happens to
        let schema = json!({
            "$defs": {
                "b": { "type": "string" },
                "inner": {
                    "$id": "https://example.com/inner",
                    "properties": { "p": { "$ref": "#/$defs/b" } }
                }
            }
        });

        // WHEN inspected
        // THEN the inner fragment is resolved against the inner resource, so the
        // outer `$defs/b` does not rescue it
        assert_eq!(
            SchemaBounds::inspect(&schema),
            SchemaBounds::OutOfBounds {
                unresolved_refs: vec!["#/$defs/b".to_string()]
            }
        );
    }

    #[test]
    fn a_dangling_ref_in_the_output_schema_is_reported_qualified() {
        // GIVEN a bounded input schema and an output schema that dangles
        let input = json!({ "type": "object" });
        let output = json!({ "properties": { "r": { "$ref": "#/$defs/Absent" } } });

        // WHEN the descriptor's two documents are inspected together
        // THEN the output pointer is reported, named for the document it came from
        assert_eq!(
            SchemaBounds::inspect_descriptor(&input, Some(&output)),
            SchemaBounds::OutOfBounds {
                unresolved_refs: vec!["outputSchema#/$defs/Absent".to_string()]
            }
        );
    }

    #[test]
    fn a_descriptor_with_no_output_schema_is_judged_on_its_input_alone() {
        // GIVEN a bounded input schema and no output schema at all
        let input = json!({
            "$defs": { "T": { "type": "string" } },
            "properties": { "t": { "$ref": "#/$defs/T" } }
        });

        // WHEN inspected
        // THEN the absent document adds nothing
        assert_eq!(
            SchemaBounds::inspect_descriptor(&input, None),
            SchemaBounds::Within
        );
    }
}
