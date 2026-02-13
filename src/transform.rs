//! Response transform pipeline for stripping noise from API responses.
//!
//! Transforms sit between the executor response and the MCP response,
//! configured per-capability in the YAML `transform` section.
//!
//! Pipeline order (fixed): **project -> rename -> redact -> format**
//!
//! ```text
//! Executor Response
//!       │
//!       ▼
//! ┌─────────────┐
//! │  Transform  │──▶ project ──▶ rename ──▶ redact ──▶ format
//! │  Pipeline   │
//! └─────────────┘
//!       │
//!       ▼
//! MCP Response (lean)
//! ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ============================================================================
// Configuration types (deserialized from YAML)
// ============================================================================

/// Complete transform configuration for a capability.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransformConfig {
    /// Field projection (allowlist of JSON paths to keep).
    #[serde(default)]
    pub project: Vec<String>,

    /// Field renaming map (`old_path` -> `new_name`).
    #[serde(default)]
    pub rename: HashMap<String, String>,

    /// PII/sensitive data redaction rules.
    #[serde(default)]
    pub redact: Vec<RedactRule>,

    /// Output format conversion.
    #[serde(default)]
    pub format: Option<FormatConfig>,
}

/// A single redaction rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactRule {
    /// Regex pattern to match.
    pub pattern: String,
    /// Replacement string.
    pub replacement: String,
}

/// Output format configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatConfig {
    /// Format type.
    #[serde(rename = "type")]
    pub format_type: FormatType,
    /// Template string (for `type=template`).
    #[serde(default)]
    pub template: Option<String>,
}

/// Supported format transformations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FormatType {
    /// Flatten nested objects to dot-separated top-level keys.
    Flat,
    /// Keep nested structure (default, noop).
    Nested,
    /// Apply a `{{var}}` template.
    Template,
}

// ============================================================================
// JSON path types (shared with playbook module)
// ============================================================================

/// A single segment in a parsed JSON path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonPathSegment {
    /// Object key: `"foo"`.
    Key(String),
    /// Array wildcard: `"[]"`.
    ArrayWildcard,
    /// Array index: `"[0]"`.
    ArrayIndex(usize),
}

/// A parsed JSON path like `"web.results[].title"`.
pub type JsonPath = Vec<JsonPathSegment>;

/// Parse a dot-separated JSON path string into segments.
///
/// Supports:
/// - `"foo.bar"` -> `[Key("foo"), Key("bar")]`
/// - `"results[].title"` -> `[Key("results"), ArrayWildcard, Key("title")]`
/// - `"items[0].name"` -> `[Key("items"), ArrayIndex(0), Key("name")]`
#[must_use]
pub fn parse_json_path(path: &str) -> JsonPath {
    let mut segments = Vec::new();
    for part in path.split('.') {
        if part.is_empty() {
            continue;
        }
        if let Some(before_bracket) = part.strip_suffix("[]") {
            if !before_bracket.is_empty() {
                segments.push(JsonPathSegment::Key(before_bracket.to_string()));
            }
            segments.push(JsonPathSegment::ArrayWildcard);
        } else if let Some(idx_start) = part.find('[') {
            let key = &part[..idx_start];
            if !key.is_empty() {
                segments.push(JsonPathSegment::Key(key.to_string()));
            }
            let idx_str = &part[idx_start + 1..part.len() - 1];
            if let Ok(idx) = idx_str.parse::<usize>() {
                segments.push(JsonPathSegment::ArrayIndex(idx));
            }
        } else {
            segments.push(JsonPathSegment::Key(part.to_string()));
        }
    }
    segments
}

/// Resolve a parsed JSON path against a value, collecting all matched leaf values.
///
/// Array wildcards expand into every element of the matched array.
#[must_use]
pub fn resolve_path(value: &Value, path: &[JsonPathSegment]) -> Vec<Value> {
    if path.is_empty() {
        return vec![value.clone()];
    }

    match &path[0] {
        JsonPathSegment::Key(key) => match value.get(key.as_str()) {
            Some(child) => resolve_path(child, &path[1..]),
            None => vec![],
        },
        JsonPathSegment::ArrayWildcard => match value.as_array() {
            Some(arr) => arr.iter().flat_map(|v| resolve_path(v, &path[1..])).collect(),
            None => vec![],
        },
        JsonPathSegment::ArrayIndex(idx) => match value.as_array() {
            Some(arr) => match arr.get(*idx) {
                Some(child) => resolve_path(child, &path[1..]),
                None => vec![],
            },
            None => vec![],
        },
    }
}

/// Resolve a path to a single value (first match), returning `Value::Null` if none.
#[must_use]
pub fn resolve_path_single(value: &Value, path: &[JsonPathSegment]) -> Value {
    let results = resolve_path(value, path);
    if results.len() == 1 {
        results.into_iter().next().unwrap_or(Value::Null)
    } else if results.is_empty() {
        Value::Null
    } else {
        Value::Array(results)
    }
}

pub mod pipeline;
pub use pipeline::TransformPipeline;
