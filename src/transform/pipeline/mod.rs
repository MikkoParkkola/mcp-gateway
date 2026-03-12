//! Transform pipeline execution engine.

use regex::Regex;
use serde_json::Value;

use super::{
    TransformConfig, FormatConfig, FormatType, JsonPath,
    resolve_path, resolve_path_single, parse_json_path
};


// ============================================================================
// Compiled pipeline
// ============================================================================

/// Pre-compiled redaction rule with a ready-to-use regex.
struct CompiledRedaction {
    regex: Regex,
    replacement: String,
}

/// Compiled transform pipeline (ready to execute).
///
/// Construct via [`TransformPipeline::compile`] from a [`TransformConfig`].
pub struct TransformPipeline {
    projections: Vec<(String, JsonPath)>,
    renames: Vec<(String, String)>,
    redactions: Vec<CompiledRedaction>,
    format: Option<FormatConfig>,
}

impl TransformPipeline {
    /// Compile a `TransformConfig` into an executable pipeline.
    ///
    /// Invalid regex patterns in redact rules are silently skipped
    /// (logged at debug level in production).
    #[must_use]
    pub fn compile(config: &TransformConfig) -> Self {
        let projections: Vec<(String, JsonPath)> = config
            .project
            .iter()
            .map(|p| (p.clone(), parse_json_path(p)))
            .collect();

        let renames: Vec<(String, String)> = config
            .rename
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let redactions: Vec<CompiledRedaction> = config
            .redact
            .iter()
            .filter_map(|rule| {
                Regex::new(&rule.pattern).ok().map(|regex| CompiledRedaction {
                    regex,
                    replacement: rule.replacement.clone(),
                })
            })
            .collect();

        Self {
            projections,
            renames,
            redactions,
            format: config.format.clone(),
        }
    }

    /// Returns `true` if this pipeline has no operations to perform.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.projections.is_empty()
            && self.renames.is_empty()
            && self.redactions.is_empty()
            && self.format.is_none()
    }

    /// Apply the full transform pipeline to a JSON value.
    ///
    /// Pipeline order: project -> rename -> redact -> format.
    #[must_use]
    pub fn apply(&self, value: Value) -> Value {
        if self.is_noop() {
            return value;
        }

        let value = self.apply_project(value);
        let value = self.apply_rename(value);
        let value = self.apply_redact(value);
        self.apply_format(value)
    }

    // ── Step 1: Projection ──────────────────────────────────────────────

    fn apply_project(&self, value: Value) -> Value {
        if self.projections.is_empty() {
            return value;
        }

        let mut result = serde_json::Map::new();
        for (raw_path, parsed_path) in &self.projections {
            let resolved = resolve_path(&value, parsed_path);
            if resolved.is_empty() {
                continue;
            }

            // Use the last segment as the key, or the full path for nested.
            let key = leaf_key(raw_path);

            if resolved.len() == 1 {
                result.insert(key, resolved.into_iter().next().unwrap_or(Value::Null));
            } else {
                result.insert(key, Value::Array(resolved));
            }
        }
        Value::Object(result)
    }

    // ── Step 2: Rename ──────────────────────────────────────────────────

    fn apply_rename(&self, value: Value) -> Value {
        if self.renames.is_empty() {
            return value;
        }

        let Value::Object(mut map) = value else {
            return value;
        };

        for (old_key, new_key) in &self.renames {
            // Support both flat keys and the leaf portion of dotted paths.
            let effective_old = leaf_key(old_key);
            if let Some(val) = map.remove(&effective_old) {
                map.insert(new_key.clone(), val);
            }
        }

        Value::Object(map)
    }

    // ── Step 3: Redact ──────────────────────────────────────────────────

    fn apply_redact(&self, value: Value) -> Value {
        if self.redactions.is_empty() {
            return value;
        }
        self.redact_recursive(value)
    }

    fn redact_recursive(&self, value: Value) -> Value {
        match value {
            Value::String(s) => {
                let mut result = s;
                for redaction in &self.redactions {
                    result = redaction
                        .regex
                        .replace_all(&result, redaction.replacement.as_str())
                        .into_owned();
                }
                Value::String(result)
            }
            Value::Array(arr) => {
                Value::Array(arr.into_iter().map(|v| self.redact_recursive(v)).collect())
            }
            Value::Object(map) => Value::Object(
                map.into_iter()
                    .map(|(k, v)| (k, self.redact_recursive(v)))
                    .collect(),
            ),
            other => other,
        }
    }

    // ── Step 4: Format ──────────────────────────────────────────────────

    fn apply_format(&self, value: Value) -> Value {
        let Some(ref config) = self.format else {
            return value;
        };

        match config.format_type {
            FormatType::Flat => flatten_value(&value),
            FormatType::Nested => value, // noop
            FormatType::Template => {
                if let Some(ref template) = config.template {
                    let rendered = render_template(template, &value);
                    Value::String(rendered)
                } else {
                    value
                }
            }
        }
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Extract the leaf key from a dotted path for use as a result key.
///
/// `"web.results[].title"` -> `"title"`
/// `"query.original"` -> `"original"`
/// `"simple"` -> `"simple"`
fn leaf_key(path: &str) -> String {
    let stripped = path.trim_end_matches("[]");
    stripped
        .rsplit_once('.')
        .map_or(stripped, |(_, leaf)| leaf)
        .to_string()
}

/// Flatten a nested JSON object into dot-separated top-level keys.
fn flatten_value(value: &Value) -> Value {
    let mut result = serde_json::Map::new();
    flatten_recursive(value, String::new(), &mut result);
    Value::Object(result)
}

fn flatten_recursive(value: &Value, prefix: String, output: &mut serde_json::Map<String, Value>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let new_prefix = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_recursive(v, new_prefix, output);
            }
        }
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let new_prefix = format!("{prefix}.{i}");
                flatten_recursive(v, new_prefix, output);
            }
        }
        _ => {
            output.insert(prefix, value.clone());
        }
    }
}

/// Simple `{{var}}` template rendering against a JSON value.
///
/// Supports dotted paths: `"{{results.0.title}}"`.
fn render_template(template: &str, value: &Value) -> String {
    let mut result = template.to_string();
    // Find all {{path}} references
    let re = Regex::new(r"\{\{(\w[\w.]*)\}\}").expect("static regex");
    for cap in re.captures_iter(template) {
        let full_match = &cap[0];
        let path_str = &cap[1];
        let path = parse_json_path(path_str);
        let resolved = resolve_path_single(value, &path);
        let replacement = match &resolved {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => String::new(),
            other => other.to_string(),
        };
        result = result.replace(full_match, &replacement);
    }
    result
}

// ============================================================================
// Tests
// ============================================================================


#[cfg(test)]
mod tests;
