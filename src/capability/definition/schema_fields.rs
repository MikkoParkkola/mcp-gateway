// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! JSON Schema search-token extraction.

/// Extract searchable field names and descriptions from a JSON Schema object.
///
/// Walks the `properties` map (one level deep) and collects:
/// - each property name (e.g. `symbol`, `exchange`)
/// - the `description` string of each property, split into words
/// - the top-level schema `description` string, split into words
///
/// Only non-empty, non-duplicate tokens are returned; all tokens are
/// lowercased so callers can do case-insensitive matching cheaply.
///
/// # Example
///
/// ```json
/// {
///   "type": "object",
///   "description": "Stock query parameters",
///   "properties": {
///     "symbol": { "type": "string", "description": "Stock ticker symbol" },
///     "exchange": { "type": "string" }
///   }
/// }
/// ```
///
/// Returns: `["symbol", "exchange", "stock", "ticker", "query", "parameters"]`
#[must_use]
pub fn extract_schema_fields(schema: &serde_json::Value) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut fields = Vec::new();

    // Collect a token, deduplicating across the whole result set.
    let mut push = |token: &str| {
        let token = token.trim().to_lowercase();
        if !token.is_empty() && seen.insert(token.clone()) {
            fields.push(token);
        }
    };

    collect_schema_tokens(schema, &mut push);
    fields
}

/// Collect tokens from a JSON Schema node (one level of `properties`).
fn collect_schema_tokens(schema: &serde_json::Value, push: &mut impl FnMut(&str)) {
    // Top-level description words
    if let Some(desc) = schema.get("description").and_then(|v| v.as_str()) {
        push_words(desc, push);
    }

    // Property names and their descriptions
    if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
        for (name, prop_schema) in props {
            push(name);
            if let Some(desc) = prop_schema.get("description").and_then(|v| v.as_str()) {
                push_words(desc, push);
            }
        }
    }
}

fn push_words(desc: &str, push: &mut impl FnMut(&str)) {
    for word in desc.split_whitespace() {
        let clean = word.trim_matches(|c: char| !c.is_alphanumeric());
        push(clean);
    }
}
