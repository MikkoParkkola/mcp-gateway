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
mod tests {
    use std::collections::HashMap;

    use super::*;
    use super::super::{JsonPathSegment, RedactRule};
    use serde_json::json;

    // ── parse_json_path ─────────────────────────────────────────────────

    #[test]
    fn parse_simple_key() {
        let path = parse_json_path("name");
        assert_eq!(path, vec![JsonPathSegment::Key("name".to_string())]);
    }

    #[test]
    fn parse_dotted_path() {
        let path = parse_json_path("web.results");
        assert_eq!(
            path,
            vec![
                JsonPathSegment::Key("web".to_string()),
                JsonPathSegment::Key("results".to_string()),
            ]
        );
    }

    #[test]
    fn parse_array_wildcard() {
        let path = parse_json_path("results[].title");
        assert_eq!(
            path,
            vec![
                JsonPathSegment::Key("results".to_string()),
                JsonPathSegment::ArrayWildcard,
                JsonPathSegment::Key("title".to_string()),
            ]
        );
    }

    #[test]
    fn parse_array_index() {
        let path = parse_json_path("items[0].name");
        assert_eq!(
            path,
            vec![
                JsonPathSegment::Key("items".to_string()),
                JsonPathSegment::ArrayIndex(0),
                JsonPathSegment::Key("name".to_string()),
            ]
        );
    }

    #[test]
    fn parse_nested_wildcard() {
        let path = parse_json_path("web.results[].extra_snippets[]");
        assert_eq!(
            path,
            vec![
                JsonPathSegment::Key("web".to_string()),
                JsonPathSegment::Key("results".to_string()),
                JsonPathSegment::ArrayWildcard,
                JsonPathSegment::Key("extra_snippets".to_string()),
                JsonPathSegment::ArrayWildcard,
            ]
        );
    }

    #[test]
    fn parse_empty_path() {
        let path = parse_json_path("");
        assert!(path.is_empty());
    }

    // ── resolve_path ────────────────────────────────────────────────────

    #[test]
    fn resolve_simple_key() {
        let data = json!({"name": "Alice"});
        let path = parse_json_path("name");
        let result = resolve_path(&data, &path);
        assert_eq!(result, vec![json!("Alice")]);
    }

    #[test]
    fn resolve_nested_key() {
        let data = json!({"web": {"results": [1, 2, 3]}});
        let path = parse_json_path("web.results");
        let result = resolve_path(&data, &path);
        assert_eq!(result, vec![json!([1, 2, 3])]);
    }

    #[test]
    fn resolve_array_wildcard() {
        let data = json!({"items": [{"name": "a"}, {"name": "b"}]});
        let path = parse_json_path("items[].name");
        let result = resolve_path(&data, &path);
        assert_eq!(result, vec![json!("a"), json!("b")]);
    }

    #[test]
    fn resolve_array_index() {
        let data = json!({"items": [{"name": "a"}, {"name": "b"}]});
        let path = parse_json_path("items[1].name");
        let result = resolve_path(&data, &path);
        assert_eq!(result, vec![json!("b")]);
    }

    #[test]
    fn resolve_missing_key_returns_empty() {
        let data = json!({"name": "Alice"});
        let path = parse_json_path("age");
        let result = resolve_path(&data, &path);
        assert!(result.is_empty());
    }

    #[test]
    fn resolve_out_of_bounds_index_returns_empty() {
        let data = json!({"items": [1]});
        let path = parse_json_path("items[5]");
        let result = resolve_path(&data, &path);
        assert!(result.is_empty());
    }

    #[test]
    fn resolve_path_single_scalar() {
        let data = json!({"query": {"original": "rust"}});
        let path = parse_json_path("query.original");
        let result = resolve_path_single(&data, &path);
        assert_eq!(result, json!("rust"));
    }

    #[test]
    fn resolve_path_single_missing() {
        let data = json!({});
        let path = parse_json_path("nonexistent");
        let result = resolve_path_single(&data, &path);
        assert_eq!(result, Value::Null);
    }

    #[test]
    fn resolve_path_single_multiple_returns_array() {
        let data = json!({"items": [{"v": 1}, {"v": 2}]});
        let path = parse_json_path("items[].v");
        let result = resolve_path_single(&data, &path);
        assert_eq!(result, json!([1, 2]));
    }

    // ── leaf_key ────────────────────────────────────────────────────────

    #[test]
    fn leaf_key_simple() {
        assert_eq!(leaf_key("name"), "name");
    }

    #[test]
    fn leaf_key_dotted() {
        assert_eq!(leaf_key("query.original"), "original");
    }

    #[test]
    fn leaf_key_with_wildcard() {
        assert_eq!(leaf_key("web.results[].title"), "title");
    }

    #[test]
    fn leaf_key_wildcard_only() {
        assert_eq!(leaf_key("results[]"), "results");
    }

    // ── TransformPipeline::compile + is_noop ────────────────────────────

    #[test]
    fn default_config_produces_noop_pipeline() {
        let config = TransformConfig::default();
        let pipeline = TransformPipeline::compile(&config);
        assert!(pipeline.is_noop());
    }

    #[test]
    fn noop_pipeline_returns_input_unchanged() {
        let config = TransformConfig::default();
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"keep": "this", "nested": {"deep": true}});
        let output = pipeline.apply(input.clone());
        assert_eq!(output, input);
    }

    #[test]
    fn pipeline_with_projections_is_not_noop() {
        let config = TransformConfig {
            project: vec!["name".to_string()],
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        assert!(!pipeline.is_noop());
    }

    // ── Projection ──────────────────────────────────────────────────────

    #[test]
    fn project_keeps_only_listed_fields() {
        let config = TransformConfig {
            project: vec!["name".to_string(), "age".to_string()],
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"name": "Alice", "age": 30, "secret": "hidden"});
        let output = pipeline.apply(input);
        assert_eq!(output, json!({"name": "Alice", "age": 30}));
    }

    #[test]
    fn project_nested_paths() {
        let config = TransformConfig {
            project: vec!["query.original".to_string()],
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"query": {"original": "rust", "altered": "Rust lang"}, "extra": 42});
        let output = pipeline.apply(input);
        assert_eq!(output, json!({"original": "rust"}));
    }

    #[test]
    fn project_array_wildcard() {
        let config = TransformConfig {
            project: vec!["items[].name".to_string()],
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"items": [{"name": "a", "x": 1}, {"name": "b", "x": 2}]});
        let output = pipeline.apply(input);
        assert_eq!(output, json!({"name": ["a", "b"]}));
    }

    #[test]
    fn project_missing_field_is_omitted() {
        let config = TransformConfig {
            project: vec!["nonexistent".to_string()],
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"real": "data"});
        let output = pipeline.apply(input);
        assert_eq!(output, json!({}));
    }

    // ── Rename ──────────────────────────────────────────────────────────

    #[test]
    fn rename_flat_keys() {
        let config = TransformConfig {
            rename: HashMap::from([("old_name".to_string(), "new_name".to_string())]),
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"old_name": "value", "other": 42});
        let output = pipeline.apply(input);
        assert_eq!(output, json!({"new_name": "value", "other": 42}));
    }

    #[test]
    fn rename_dotted_path_uses_leaf() {
        let config = TransformConfig {
            rename: HashMap::from([("query.original".to_string(), "query".to_string())]),
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        // After projection, the key is the leaf "original"
        let input = json!({"original": "rust search"});
        let output = pipeline.apply(input);
        assert_eq!(output, json!({"query": "rust search"}));
    }

    #[test]
    fn rename_missing_key_is_noop() {
        let config = TransformConfig {
            rename: HashMap::from([("missing".to_string(), "new".to_string())]),
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"present": "value"});
        let output = pipeline.apply(input);
        assert_eq!(output, json!({"present": "value"}));
    }

    #[test]
    fn rename_non_object_value_unchanged() {
        let config = TransformConfig {
            rename: HashMap::from([("x".to_string(), "y".to_string())]),
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!("a string");
        let output = pipeline.apply(input.clone());
        assert_eq!(output, input);
    }

    // ── Redact ──────────────────────────────────────────────────────────

    #[test]
    fn redact_email_in_string() {
        let config = TransformConfig {
            redact: vec![RedactRule {
                pattern: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b".to_string(),
                replacement: "[EMAIL]".to_string(),
            }],
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"msg": "Contact alice@example.com for info"});
        let output = pipeline.apply(input);
        assert_eq!(output, json!({"msg": "Contact [EMAIL] for info"}));
    }

    #[test]
    fn redact_ssn_pattern() {
        let config = TransformConfig {
            redact: vec![RedactRule {
                pattern: r"\b\d{3}-\d{2}-\d{4}\b".to_string(),
                replacement: "[SSN]".to_string(),
            }],
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"data": "SSN is 123-45-6789"});
        let output = pipeline.apply(input);
        assert_eq!(output, json!({"data": "SSN is [SSN]"}));
    }

    #[test]
    fn redact_recursive_into_arrays() {
        let config = TransformConfig {
            redact: vec![RedactRule {
                pattern: r"secret".to_string(),
                replacement: "[REDACTED]".to_string(),
            }],
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"items": ["this is secret", {"note": "another secret"}]});
        let output = pipeline.apply(input);
        assert_eq!(
            output,
            json!({"items": ["this is [REDACTED]", {"note": "another [REDACTED]"}]})
        );
    }

    #[test]
    fn redact_non_string_values_unchanged() {
        let config = TransformConfig {
            redact: vec![RedactRule {
                pattern: r"123".to_string(),
                replacement: "[NUM]".to_string(),
            }],
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"num": 123, "bool": true, "null": null});
        let output = pipeline.apply(input.clone());
        assert_eq!(output, input);
    }

    #[test]
    fn redact_invalid_regex_skipped() {
        let config = TransformConfig {
            redact: vec![
                RedactRule {
                    pattern: r"[invalid".to_string(), // bad regex
                    replacement: "X".to_string(),
                },
                RedactRule {
                    pattern: r"good".to_string(),
                    replacement: "GREAT".to_string(),
                },
            ],
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        assert_eq!(pipeline.redactions.len(), 1); // only the valid one
        let input = json!({"msg": "this is good"});
        let output = pipeline.apply(input);
        assert_eq!(output, json!({"msg": "this is GREAT"}));
    }

    #[test]
    fn redact_multiple_patterns() {
        let config = TransformConfig {
            redact: vec![
                RedactRule {
                    pattern: r"foo".to_string(),
                    replacement: "X".to_string(),
                },
                RedactRule {
                    pattern: r"bar".to_string(),
                    replacement: "Y".to_string(),
                },
            ],
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"msg": "foo and bar"});
        let output = pipeline.apply(input);
        assert_eq!(output, json!({"msg": "X and Y"}));
    }

    // ── Format: Flat ────────────────────────────────────────────────────

    #[test]
    fn format_flat_simple() {
        let config = TransformConfig {
            format: Some(FormatConfig {
                format_type: FormatType::Flat,
                template: None,
            }),
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"a": {"b": 1, "c": 2}});
        let output = pipeline.apply(input);
        assert_eq!(output, json!({"a.b": 1, "a.c": 2}));
    }

    #[test]
    fn format_flat_with_array() {
        let config = TransformConfig {
            format: Some(FormatConfig {
                format_type: FormatType::Flat,
                template: None,
            }),
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"items": ["a", "b"]});
        let output = pipeline.apply(input);
        assert_eq!(output, json!({"items.0": "a", "items.1": "b"}));
    }

    #[test]
    fn format_flat_scalar() {
        let config = TransformConfig {
            format: Some(FormatConfig {
                format_type: FormatType::Flat,
                template: None,
            }),
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"x": 42});
        let output = pipeline.apply(input);
        assert_eq!(output, json!({"x": 42}));
    }

    // ── Format: Nested (noop) ───────────────────────────────────────────

    #[test]
    fn format_nested_is_noop() {
        let config = TransformConfig {
            format: Some(FormatConfig {
                format_type: FormatType::Nested,
                template: None,
            }),
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"a": {"b": 1}});
        let output = pipeline.apply(input.clone());
        assert_eq!(output, input);
    }

    // ── Format: Template ────────────────────────────────────────────────

    #[test]
    fn format_template_basic() {
        let config = TransformConfig {
            format: Some(FormatConfig {
                format_type: FormatType::Template,
                template: Some("Hello, {{name}}!".to_string()),
            }),
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"name": "World"});
        let output = pipeline.apply(input);
        assert_eq!(output, json!("Hello, World!"));
    }

    #[test]
    fn format_template_nested_path() {
        let config = TransformConfig {
            format: Some(FormatConfig {
                format_type: FormatType::Template,
                template: Some("Query: {{query.original}}".to_string()),
            }),
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"query": {"original": "Rust MCP"}});
        let output = pipeline.apply(input);
        assert_eq!(output, json!("Query: Rust MCP"));
    }

    #[test]
    fn format_template_missing_var_renders_empty() {
        let config = TransformConfig {
            format: Some(FormatConfig {
                format_type: FormatType::Template,
                template: Some("Value: {{missing}}".to_string()),
            }),
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({});
        let output = pipeline.apply(input);
        assert_eq!(output, json!("Value: "));
    }

    #[test]
    fn format_template_none_returns_input() {
        let config = TransformConfig {
            format: Some(FormatConfig {
                format_type: FormatType::Template,
                template: None,
            }),
            ..Default::default()
        };
        let pipeline = TransformPipeline::compile(&config);
        let input = json!({"data": true});
        let output = pipeline.apply(input.clone());
        assert_eq!(output, input);
    }

    // ── Full pipeline integration ───────────────────────────────────────

    #[test]
    fn full_pipeline_project_rename_redact() {
        let config = TransformConfig {
            project: vec![
                "web.results[].title".to_string(),
                "web.results[].url".to_string(),
                "query.original".to_string(),
            ],
            rename: HashMap::from([
                ("web.results".to_string(), "results".to_string()),
                ("query.original".to_string(), "query".to_string()),
            ]),
            redact: vec![RedactRule {
                pattern: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b".to_string(),
                replacement: "[EMAIL]".to_string(),
            }],
            format: None,
        };
        let pipeline = TransformPipeline::compile(&config);

        let input = json!({
            "query": {"original": "search query", "altered": "ignore"},
            "web": {
                "results": [
                    {"title": "Result 1", "url": "https://a.com", "extra": "noise"},
                    {"title": "Contact user@test.com", "url": "https://b.com", "extra": "noise2"}
                ]
            },
            "noise": "removed"
        });

        let output = pipeline.apply(input);

        // After project: {title: [...], url: [...], original: "search query"}
        // After rename: original->query
        // After redact: email in title is masked
        assert_eq!(output["query"], json!("search query"));
        let titles = output["title"].as_array().unwrap();
        assert_eq!(titles[0], json!("Result 1"));
        assert_eq!(titles[1], json!("Contact [EMAIL]"));
    }

    // ── YAML deserialization ────────────────────────────────────────────

    #[test]
    fn deserialize_transform_config_from_yaml() {
        let yaml = r"
project:
  - web.results[].title
  - web.results[].url
rename:
  web.results: results
redact:
  - pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    replacement: '[SSN]'
format:
  type: flat
";
        let config: TransformConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.project.len(), 2);
        assert_eq!(config.rename.len(), 1);
        assert_eq!(config.redact.len(), 1);
        assert!(config.format.is_some());
    }

    #[test]
    fn deserialize_empty_yaml_produces_default() {
        let config: TransformConfig = serde_yaml::from_str("{}").unwrap();
        assert!(config.project.is_empty());
        assert!(config.rename.is_empty());
        assert!(config.redact.is_empty());
        assert!(config.format.is_none());
    }

    // ── flatten_value ───────────────────────────────────────────────────

    #[test]
    fn flatten_deeply_nested() {
        let input = json!({"a": {"b": {"c": 1}}});
        let output = flatten_value(&input);
        assert_eq!(output, json!({"a.b.c": 1}));
    }

    #[test]
    fn flatten_empty_object() {
        let input = json!({});
        let output = flatten_value(&input);
        assert_eq!(output, json!({}));
    }

    // ── render_template ─────────────────────────────────────────────────

    #[test]
    fn render_template_numeric_value() {
        let value = json!({"count": 42});
        let result = render_template("Found {{count}} items", &value);
        assert_eq!(result, "Found 42 items");
    }

    #[test]
    fn render_template_no_placeholders() {
        let value = json!({});
        let result = render_template("no vars here", &value);
        assert_eq!(result, "no vars here");
    }

    #[test]
    fn render_template_boolean_value() {
        let value = json!({"ok": true});
        let result = render_template("Status: {{ok}}", &value);
        assert_eq!(result, "Status: true");
    }
}
