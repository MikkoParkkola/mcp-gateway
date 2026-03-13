//! Variable interpolation for chain step inputs.
//!
//! Resolves `$step_name.json.path` and `$inputs.key` references in JSON values,
//! supporting both pure variable references (type-preserving) and embedded
//! references within string templates (rendered as strings).

use std::collections::HashMap;

use serde_json::Value;

// ============================================================================
// Public API
// ============================================================================

/// Recursively interpolate `$step_name.json.path` variables in a JSON value.
///
/// - `outputs`: accumulated step results, keyed by step name.
/// - `inputs`: top-level chain inputs, accessible as `$inputs.key`.
pub fn interpolate_inputs(
    value: &Value,
    outputs: &HashMap<String, Value>,
    inputs: &Value,
) -> Value {
    match value {
        Value::String(s) => interpolate_string(s, outputs, inputs),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), interpolate_inputs(v, outputs, inputs)))
                .collect(),
        ),
        Value::Array(arr) => Value::Array(
            arr.iter()
                .map(|v| interpolate_inputs(v, outputs, inputs))
                .collect(),
        ),
        other => other.clone(),
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Interpolate variable references within a single string.
///
/// - Pure reference (`"$step.key"`) → resolved value with original JSON type.
/// - Embedded reference (`"prefix $step.key suffix"`) → rendered as string.
fn interpolate_string(s: &str, outputs: &HashMap<String, Value>, inputs: &Value) -> Value {
    let trimmed = s.trim();

    if looks_like_pure_ref(trimmed) {
        return resolve_var(trimmed, outputs, inputs);
    }

    let mut result = s.to_string();
    for var_ref in extract_var_refs(s) {
        let resolved = resolve_var(&var_ref, outputs, inputs);
        let replacement = value_to_string(&resolved);
        result = result.replace(&var_ref, &replacement);
    }
    Value::String(result)
}

/// `true` when `s` is a single variable reference (starts with `$`, no spaces).
fn looks_like_pure_ref(s: &str) -> bool {
    s.starts_with('$') && !s.contains(' ') && !s.contains('+')
}

/// Resolve `$inputs.query` or `$search.results[0].title` against runtime state.
fn resolve_var(var_ref: &str, outputs: &HashMap<String, Value>, inputs: &Value) -> Value {
    let trimmed = var_ref.trim_start_matches('$');
    let (namespace, remainder) = trimmed.split_once('.').unwrap_or((trimmed, ""));

    let source = if namespace == "inputs" {
        inputs
    } else {
        match outputs.get(namespace) {
            Some(v) => v,
            None => return Value::Null,
        }
    };

    if remainder.is_empty() {
        return source.clone();
    }

    resolve_path(source, remainder)
}

/// Navigate a dot/bracket path through a JSON value.
pub fn resolve_path(value: &Value, path: &str) -> Value {
    let mut current = value;
    let mut owned: Value;

    for segment in tokenize_path(path) {
        match segment {
            PathSegment::Key(k) => match current {
                Value::Object(map) => match map.get(&k) {
                    Some(v) => {
                        owned = v.clone();
                        current = &owned;
                    }
                    None => return Value::Null,
                },
                _ => return Value::Null,
            },
            PathSegment::Index(i) => match current {
                Value::Array(arr) => match arr.get(i) {
                    Some(v) => {
                        owned = v.clone();
                        current = &owned;
                    }
                    None => return Value::Null,
                },
                _ => return Value::Null,
            },
        }
    }

    current.clone()
}

#[derive(Debug)]
pub(crate) enum PathSegment {
    Key(String),
    Index(usize),
}

/// Tokenize `"results[0].title"` into `[Key("results"), Index(0), Key("title")]`.
pub fn tokenize_path(path: &str) -> Vec<PathSegment> {
    let mut segments = Vec::new();
    for part in path.split('.') {
        if let Some((key, rest)) = part.split_once('[') {
            if !key.is_empty() {
                segments.push(PathSegment::Key(key.to_string()));
            }
            let idx_str = rest.trim_end_matches(']');
            if let Ok(i) = idx_str.parse::<usize>() {
                segments.push(PathSegment::Index(i));
            }
        } else {
            segments.push(PathSegment::Key(part.to_string()));
        }
    }
    segments
}

/// Extract all `$identifier.path[N]` references from a string.
pub fn extract_var_refs(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut refs = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] != '$' {
            i += 1;
            continue;
        }
        let start = i;
        i += 1;
        while i < chars.len()
            && (chars[i].is_alphanumeric()
                || chars[i] == '_'
                || chars[i] == '.'
                || chars[i] == '['
                || chars[i] == ']')
        {
            i += 1;
        }
        if i > start + 1 {
            refs.push(chars[start..i].iter().collect());
        }
    }
    refs
}

/// Render a JSON value as a string for text interpolation.
pub fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}
