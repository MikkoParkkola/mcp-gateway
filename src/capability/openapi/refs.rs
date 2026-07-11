// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `OpenAPI` `$ref` resolution against the components section.
//!
//! Single responsibility: dereference parameter, request-body, and schema
//! `$ref` pointers into inline definitions.

use serde_json::Value;
use tracing::warn;

use super::model::{OpenApiComponents, OpenApiParameter, OpenApiRequestBody};

/// Resolve a parameter `$ref` against `components.parameters`. Non-ref
/// parameters are returned unchanged. Refs that cannot be resolved are
/// dropped (with a warning) so they do not end up in the generated schema
/// with an empty name.
pub(crate) fn resolve_parameter(
    param: &OpenApiParameter,
    components: &OpenApiComponents,
) -> Option<OpenApiParameter> {
    if let Some(ref reference) = param.reference {
        let key = reference.trim_start_matches("#/components/parameters/");
        if let Some(resolved) = components.parameters.get(key) {
            Some(resolved.clone())
        } else {
            warn!(reference = %reference, "Unresolved parameter $ref");
            None
        }
    } else if param.name.is_empty() {
        None
    } else {
        Some(param.clone())
    }
}

/// Resolve a request body `$ref` against `components.requestBodies`.
pub(crate) fn resolve_request_body(
    body: &OpenApiRequestBody,
    components: &OpenApiComponents,
) -> Option<OpenApiRequestBody> {
    if let Some(ref reference) = body.reference {
        let key = reference.trim_start_matches("#/components/requestBodies/");
        if let Some(resolved) = components.request_bodies.get(key) {
            Some(resolved.clone())
        } else {
            warn!(reference = %reference, "Unresolved requestBody $ref");
            None
        }
    } else {
        Some(body.clone())
    }
}

/// Recursively resolve `$ref` pointers inside a JSON Schema against
/// `components.schemas`.
///
/// Only `#/components/schemas/<Name>` references are followed; unknown or
/// external refs are left in place (they become a no-op at YAML emission
/// time).  Recursion is bounded to 8 levels to prevent cycles.
pub(crate) fn resolve_schema_refs(value: &Value, components: &OpenApiComponents) -> Value {
    resolve_schema_refs_inner(value, components, 0)
}

pub(crate) fn resolve_schema_refs_inner(
    value: &Value,
    components: &OpenApiComponents,
    depth: u8,
) -> Value {
    const MAX_DEPTH: u8 = 8;
    if depth >= MAX_DEPTH {
        return value.clone();
    }
    match value {
        Value::Object(map) => {
            if let Some(Value::String(reference)) = map.get("$ref")
                && let Some(key) = reference.strip_prefix("#/components/schemas/")
                && let Some(target) = components.schemas.get(key)
            {
                return resolve_schema_refs_inner(target, components, depth + 1);
            }
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(
                    k.clone(),
                    resolve_schema_refs_inner(v, components, depth + 1),
                );
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|i| resolve_schema_refs_inner(i, components, depth + 1))
                .collect(),
        ),
        _ => value.clone(),
    }
}
