// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! Schema-shape classification for the MIK-6865 nested-key-invention surface.
//!
//! Every tool input schema is one of three risks. There is no unclassified
//! bucket: walking any JSON Schema value yields exactly one of these.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Risk class of an MCP / capability input schema.
///
/// `nested-object-array` is the Ronacher surface (array-of-objects **or** a
/// nested object parameter). The kebab-case name is the ticket's three-way
/// vocabulary; nested objects that are not in an array share the same
/// fail-closed treatment, so they share the class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SchemaShapeRisk {
    /// Only top-level scalars / enums. No arrays, no nested objects.
    Flat,
    /// Has arrays of scalars, but no nested object parameters.
    NestedScalarArray,
    /// Has an array of objects, or a nested object parameter.
    NestedObjectArray,
}

/// One row of a schema-shape audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaShapeAuditEntry {
    /// Tool name (capability name or `meta:<tool>`).
    pub tool: String,
    /// Classified shape risk.
    pub shape_risk: SchemaShapeRisk,
}

/// Classify an input JSON Schema into [`SchemaShapeRisk`].
///
/// Null / empty / non-object schemas are `flat`. Classification walks
/// `properties` and `items` and does not resolve `$ref`.
#[must_use]
pub fn classify_schema_shape(schema: &Value) -> SchemaShapeRisk {
    let mut saw_scalar_array = false;
    let mut saw_nested_object = false;
    walk_schema(schema, 0, &mut saw_scalar_array, &mut saw_nested_object);
    if saw_nested_object {
        SchemaShapeRisk::NestedObjectArray
    } else if saw_scalar_array {
        SchemaShapeRisk::NestedScalarArray
    } else {
        SchemaShapeRisk::Flat
    }
}

/// Classify every `(tool, schema)` pair. The result is sorted by tool name.
///
/// Every input is classified; the enum has no "unknown" variant, so an
/// unclassified tool cannot be represented.
#[must_use]
pub fn audit_schema_shapes<'a, I>(tools: I) -> Vec<SchemaShapeAuditEntry>
where
    I: IntoIterator<Item = (&'a str, &'a Value)>,
{
    let mut entries: Vec<SchemaShapeAuditEntry> = tools
        .into_iter()
        .map(|(tool, schema)| SchemaShapeAuditEntry {
            tool: tool.to_string(),
            shape_risk: classify_schema_shape(schema),
        })
        .collect();
    entries.sort_by(|a, b| a.tool.cmp(&b.tool));
    entries
}

const MAX_WALK_DEPTH: u8 = 8;

fn walk_schema(
    schema: &Value,
    depth: u8,
    saw_scalar_array: &mut bool,
    saw_nested_object: &mut bool,
) {
    if depth >= MAX_WALK_DEPTH {
        return;
    }
    if let Some(items) = schema.get("items") {
        classify_array_items(items, depth, saw_scalar_array, saw_nested_object);
    }
    if schema.get("type").and_then(Value::as_str) == Some("object")
        || schema.get("properties").is_some()
    {
        if depth > 0 {
            *saw_nested_object = true;
        }
        if let Some(props) = schema.get("properties").and_then(Value::as_object) {
            for prop in props.values() {
                walk_schema(
                    prop,
                    depth.saturating_add(1),
                    saw_scalar_array,
                    saw_nested_object,
                );
            }
        }
    }
}

fn classify_array_items(
    items: &Value,
    depth: u8,
    saw_scalar_array: &mut bool,
    saw_nested_object: &mut bool,
) {
    let items_type = items.get("type").and_then(Value::as_str);
    if items_type == Some("object") || items.get("properties").is_some() {
        *saw_nested_object = true;
        walk_schema(
            items,
            depth.saturating_add(1),
            saw_scalar_array,
            saw_nested_object,
        );
        return;
    }
    match items_type {
        Some("string" | "number" | "integer" | "boolean") => *saw_scalar_array = true,
        // Unspecified item type can hold objects; fail closed on classification.
        _ => *saw_nested_object = true,
    }
}
