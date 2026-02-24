//! Strict JSON Schema validator for capability tool arguments.
//!
//! Validates LLM-supplied arguments against the `schema.input` defined in a
//! capability YAML before any HTTP request is made.  The goal is to produce
//! **LLM-friendly** error messages that tell the model *exactly* what it did
//! wrong and what the valid parameters are.
//!
//! # Validation steps (in order)
//!
//! 1. **Required parameters** – every name listed under `required:` must be
//!    present and non-null.
//! 2. **Unknown parameters** – keys in the argument object that are not listed
//!    under `properties:` are rejected.
//! 3. **Type validation with coercion** – each value is checked against the
//!    declared JSON Schema type.  Safe coercions are applied automatically:
//!    - `"123"` → `123` for `integer` / `number` fields
//!    - `"true"` / `"false"` → `true` / `false` for `boolean` fields
//! 4. **Enum values** – if a property declares `enum: [...]`, the value must
//!    be one of the listed options (checked after coercion).
//! 5. **String constraints** – `minLength`, `maxLength`, and numeric
//!    `minimum` / `maximum` are checked where declared.

use std::fmt::Write as _;

use serde_json::Value;

/// A single validation violation with a human-readable, LLM-actionable message.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationViolation {
    /// Parameter name that caused the violation (empty for top-level issues).
    pub param: String,
    /// Human-readable description of the problem.
    pub message: String,
}

impl ValidationViolation {
    fn new(param: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            param: param.into(),
            message: message.into(),
        }
    }
}

/// The result of validating arguments against a schema.
#[derive(Debug, Clone)]
pub struct SchemaValidationResult {
    /// All violations found.  Empty means the arguments are valid.
    pub violations: Vec<ValidationViolation>,
    /// Arguments after safe type coercions have been applied.
    pub coerced: Value,
}

impl SchemaValidationResult {
    /// Returns `true` if there are no violations.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.violations.is_empty()
    }

    /// Format violations into an LLM-friendly error string.
    ///
    /// The message is structured to give the model exactly what it needs to fix
    /// the call, including the list of valid parameters from the schema.
    #[must_use]
    pub fn format_error(&self, schema: &Value) -> String {
        let mut out = String::from("Tool call validation failed:\n\n");

        for v in &self.violations {
            if v.param.is_empty() {
                let _ = writeln!(out, "- {}", v.message);
            } else {
                let _ = writeln!(out, "- Parameter '{}': {}", v.param, v.message);
            }
        }

        // Append the list of valid parameters as a hint.
        let valid_params = collect_valid_params(schema);
        if !valid_params.is_empty() {
            out.push_str("\nValid parameters for this tool:\n");
            for (name, info) in &valid_params {
                let _ = writeln!(out, "  - {name}: {info}");
            }
        }

        out
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Validate `arguments` against `input_schema`.
///
/// Returns a [`SchemaValidationResult`] that includes:
/// - `violations`: all problems found (empty if valid)
/// - `coerced`: the arguments after safe type coercions (use this for the
///   actual API call when `is_valid()` returns `true`)
///
/// Passing `Value::Null` or an empty object as the schema disables validation
/// (treated as "any object accepted") so capabilities without a schema continue
/// to work unchanged.
#[must_use]
pub fn validate_arguments(arguments: &Value, input_schema: &Value) -> SchemaValidationResult {
    // No schema → nothing to validate.
    if input_schema.is_null() || input_schema == &Value::Object(serde_json::Map::new()) {
        return SchemaValidationResult {
            violations: Vec::new(),
            coerced: arguments.clone(),
        };
    }

    let properties = input_schema.get("properties").and_then(Value::as_object);

    // Schema exists but has no properties → nothing to validate.
    let Some(properties) = properties else {
        return SchemaValidationResult {
            violations: Vec::new(),
            coerced: arguments.clone(),
        };
    };

    let required: Vec<&str> = input_schema
        .get("required")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .collect()
        })
        .unwrap_or_default();

    // Normalise arguments to an object; null / missing → treat as empty object.
    let arg_map = match arguments {
        Value::Object(m) => m.clone(),
        Value::Null => serde_json::Map::new(),
        _ => {
            return SchemaValidationResult {
                violations: vec![ValidationViolation::new(
                    "",
                    "Arguments must be a JSON object",
                )],
                coerced: arguments.clone(),
            };
        }
    };

    let mut violations = Vec::new();
    let mut coerced_map = serde_json::Map::new();

    // Step 1 – required parameters.
    for name in &required {
        match arg_map.get(*name) {
            None => violations.push(ValidationViolation::new(
                *name,
                "required parameter is missing",
            )),
            Some(Value::Null) => violations.push(ValidationViolation::new(
                *name,
                "required parameter must not be null",
            )),
            _ => {}
        }
    }

    // Step 2 – unknown parameters.
    for key in arg_map.keys() {
        if !properties.contains_key(key.as_str()) {
            let known: Vec<&str> = properties.keys().map(String::as_str).collect();
            violations.push(ValidationViolation::new(
                key,
                format!(
                    "unknown parameter — valid parameters are: {}",
                    known.join(", ")
                ),
            ));
        }
    }

    // Early exit: if there are unknown params or missing required, stop here so
    // the error message is clear and not cluttered by cascading type errors.
    if !violations.is_empty() {
        return SchemaValidationResult {
            violations,
            coerced: arguments.clone(),
        };
    }

    // Steps 3-5 – per-property type, enum, and constraint validation.
    for (name, prop_schema) in properties {
        let Some(raw_value) = arg_map.get(name.as_str()) else {
            // Optional parameter not provided — skip.
            continue;
        };

        if raw_value.is_null() {
            // Null is acceptable for optional params not in `required`.
            continue;
        }

        let (coerced_value, type_violations) =
            validate_property(name, raw_value, prop_schema);

        violations.extend(type_violations);
        coerced_map.insert(name.clone(), coerced_value);
    }

    // If there are type violations keep the original args (they'll be rejected).
    let coerced = if violations.is_empty() {
        Value::Object(coerced_map)
    } else {
        arguments.clone()
    };

    SchemaValidationResult { violations, coerced }
}

// ── Per-property validation ───────────────────────────────────────────────────

/// Validate a single property value against its schema.
///
/// Returns `(coerced_value, violations)`.
fn validate_property(
    name: &str,
    value: &Value,
    prop_schema: &Value,
) -> (Value, Vec<ValidationViolation>) {
    let declared_type = prop_schema.get("type").and_then(Value::as_str);
    let mut violations = Vec::new();

    // Attempt coercion first; use the coerced value for subsequent checks.
    let coerced = if let Some(ty) = declared_type {
        match try_coerce(value, ty) {
            Ok(v) => v,
            Err(msg) => {
                violations.push(ValidationViolation::new(name, msg));
                value.clone()
            }
        }
    } else {
        value.clone()
    };

    // Only proceed to enum / constraint checks if type was valid.
    if violations.is_empty() {
        // Enum check.
        if let Some(enum_values) = prop_schema.get("enum").and_then(Value::as_array) {
            if !enum_values.contains(&coerced) {
                let options: Vec<String> = enum_values
                    .iter()
                    .map(value_to_display_string)
                    .collect();
                violations.push(ValidationViolation::new(
                    name,
                    format!("must be one of: {}", options.join(", ")),
                ));
            }
        }

        // Numeric constraints.
        if let Some(num) = coerced.as_f64() {
            if let Some(min) = prop_schema.get("minimum").and_then(Value::as_f64) {
                if num < min {
                    violations.push(ValidationViolation::new(
                        name,
                        format!("must be >= {min}"),
                    ));
                }
            }
            if let Some(max) = prop_schema.get("maximum").and_then(Value::as_f64) {
                if num > max {
                    violations.push(ValidationViolation::new(
                        name,
                        format!("must be <= {max}"),
                    ));
                }
            }
        }

        // String length constraints.
        if let Some(s) = coerced.as_str() {
            let len = s.chars().count();
            if let Some(min_len) = prop_schema.get("minLength").and_then(Value::as_u64) {
                if (len as u64) < min_len {
                    violations.push(ValidationViolation::new(
                        name,
                        format!("must be at least {min_len} characters long"),
                    ));
                }
            }
            if let Some(max_len) = prop_schema.get("maxLength").and_then(Value::as_u64) {
                if (len as u64) > max_len {
                    violations.push(ValidationViolation::new(
                        name,
                        format!("must be at most {max_len} characters long"),
                    ));
                }
            }
        }
    }

    (coerced, violations)
}

// ── Type coercion ─────────────────────────────────────────────────────────────

/// Attempt to coerce `value` to the declared JSON Schema `type`.
///
/// Returns the coerced value on success or an error message on failure.
fn try_coerce(value: &Value, declared_type: &str) -> Result<Value, String> {
    match declared_type {
        "string" => coerce_to_string(value),
        "integer" => coerce_to_integer(value),
        "number" => coerce_to_number(value),
        "boolean" => coerce_to_boolean(value),
        "array" => coerce_to_array(value),
        "object" => coerce_to_object(value),
        _ => Ok(value.clone()), // Unknown type — pass through.
    }
}

fn coerce_to_string(value: &Value) -> Result<Value, String> {
    match value {
        Value::String(_) => Ok(value.clone()),
        Value::Number(n) => Ok(Value::String(n.to_string())),
        Value::Bool(b) => Ok(Value::String(b.to_string())),
        _ => Err(format!(
            "expected string, got {}",
            json_type_name(value)
        )),
    }
}

fn coerce_to_integer(value: &Value) -> Result<Value, String> {
    match value {
        Value::Number(n) if n.is_i64() || n.is_u64() => Ok(value.clone()),
        Value::Number(n) => {
            // Float with no fractional part → integer.
            if let Some(f) = n.as_f64() {
                if f.fract() == 0.0 {
                    #[allow(clippy::cast_possible_truncation)]
                    return Ok(Value::Number((f as i64).into()));
                }
            }
            Err(format!("expected integer, got float {n}"))
        }
        Value::String(s) => s
            .trim()
            .parse::<i64>()
            .map(|i| Value::Number(i.into()))
            .map_err(|_| format!("expected integer, got string \"{s}\" which is not a valid integer")),
        _ => Err(format!(
            "expected integer, got {}",
            json_type_name(value)
        )),
    }
}

fn coerce_to_number(value: &Value) -> Result<Value, String> {
    match value {
        Value::Number(_) => Ok(value.clone()),
        Value::String(s) => s
            .trim()
            .parse::<f64>()
            .ok()
            .and_then(|f| serde_json::Number::from_f64(f).map(Value::Number))
            .ok_or_else(|| {
                format!("expected number, got string \"{s}\" which is not a valid number")
            }),
        _ => Err(format!(
            "expected number, got {}",
            json_type_name(value)
        )),
    }
}

fn coerce_to_boolean(value: &Value) -> Result<Value, String> {
    match value {
        Value::Bool(_) => Ok(value.clone()),
        Value::String(s) => match s.trim().to_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(Value::Bool(true)),
            "false" | "0" | "no" => Ok(Value::Bool(false)),
            _ => Err(format!(
                "expected boolean, got string \"{s}\" — use true or false"
            )),
        },
        Value::Number(n) => match n.as_i64() {
            Some(1) => Ok(Value::Bool(true)),
            Some(0) => Ok(Value::Bool(false)),
            _ => Err(format!(
                "expected boolean, got number {n} — use true or false"
            )),
        },
        _ => Err(format!(
            "expected boolean, got {}",
            json_type_name(value)
        )),
    }
}

fn coerce_to_array(value: &Value) -> Result<Value, String> {
    match value {
        Value::Array(_) => Ok(value.clone()),
        _ => Err(format!(
            "expected array, got {}",
            json_type_name(value)
        )),
    }
}

fn coerce_to_object(value: &Value) -> Result<Value, String> {
    match value {
        Value::Object(_) => Ok(value.clone()),
        _ => Err(format!(
            "expected object, got {}",
            json_type_name(value)
        )),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn value_to_display_string(v: &Value) -> String {
    match v {
        Value::String(s) => format!("\"{s}\""),
        _ => v.to_string(),
    }
}

/// Collect valid parameter names with type/description info from a JSON Schema.
fn collect_valid_params(schema: &Value) -> Vec<(String, String)> {
    let Some(props) = schema.get("properties").and_then(Value::as_object) else {
        return Vec::new();
    };

    let required: std::collections::HashSet<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    props
        .iter()
        .map(|(name, prop)| {
            let ty = prop
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("any");
            let desc = prop
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("");
            let req = if required.contains(name.as_str()) {
                " [required]"
            } else {
                " [optional]"
            };
            let enum_hint = prop
                .get("enum")
                .and_then(Value::as_array)
                .map(|arr| {
                    let opts: Vec<String> = arr.iter().map(value_to_display_string).collect();
                    format!(" — one of: {}", opts.join(", "))
                })
                .unwrap_or_default();

            let info = format!("({ty}{req}){enum_hint}{}", if desc.is_empty() { String::new() } else { format!(" — {desc}") });
            (name.clone(), info)
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Helper ──────────────────────────────────────────────────────────────

    fn schema_with_props(props: serde_json::Value, required: &[&str]) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": props,
            "required": required
        })
    }

    // ── Required parameters ─────────────────────────────────────────────────

    #[test]
    fn required_param_missing_produces_violation() {
        // GIVEN: schema requiring "query", WHEN: args are empty
        let schema = schema_with_props(
            json!({ "query": { "type": "string" } }),
            &["query"],
        );
        let result = validate_arguments(&json!({}), &schema);

        // THEN: violation for missing required param
        assert!(!result.is_valid());
        assert_eq!(result.violations[0].param, "query");
        assert!(result.violations[0].message.contains("missing"));
    }

    #[test]
    fn required_param_null_produces_violation() {
        // GIVEN: schema requiring "symbol", WHEN: args provide null
        let schema = schema_with_props(
            json!({ "symbol": { "type": "string" } }),
            &["symbol"],
        );
        let result = validate_arguments(&json!({ "symbol": null }), &schema);

        assert!(!result.is_valid());
        assert!(result.violations[0].message.contains("null"));
    }

    #[test]
    fn required_param_present_passes() {
        // GIVEN: schema requiring "query", WHEN: args supply it
        let schema = schema_with_props(
            json!({ "query": { "type": "string" } }),
            &["query"],
        );
        let result = validate_arguments(&json!({ "query": "rust" }), &schema);

        assert!(result.is_valid());
    }

    // ── Unknown parameters ──────────────────────────────────────────────────

    #[test]
    fn unknown_param_produces_violation() {
        // GIVEN: schema with only "query", WHEN: args include "hallucinated_param"
        let schema = schema_with_props(
            json!({ "query": { "type": "string" } }),
            &["query"],
        );
        let result = validate_arguments(
            &json!({ "query": "rust", "hallucinated_param": "bad" }),
            &schema,
        );

        assert!(!result.is_valid());
        let unknown = result
            .violations
            .iter()
            .find(|v| v.param == "hallucinated_param")
            .expect("violation for hallucinated_param");
        assert!(unknown.message.contains("unknown parameter"));
    }

    #[test]
    fn unknown_param_error_lists_valid_params() {
        // GIVEN: schema with "query" only, WHEN: unknown key sent
        let schema = schema_with_props(
            json!({ "query": { "type": "string" } }),
            &[],
        );
        let result = validate_arguments(&json!({ "bad_key": "v" }), &schema);

        let v = &result.violations[0];
        // The error message must mention the valid param "query"
        assert!(v.message.contains("query"), "message: {}", v.message);
    }

    // ── Type validation ─────────────────────────────────────────────────────

    #[test]
    fn string_value_for_integer_field_is_coerced() {
        // GIVEN: "count" declared as integer, WHEN: LLM passes "10" (string)
        let schema = schema_with_props(
            json!({ "count": { "type": "integer" } }),
            &[],
        );
        let result = validate_arguments(&json!({ "count": "10" }), &schema);

        // THEN: coercion succeeds, no violations
        assert!(result.is_valid(), "violations: {:?}", result.violations);
        assert_eq!(result.coerced["count"], json!(10));
    }

    #[test]
    fn string_value_for_number_field_is_coerced() {
        // GIVEN: "price" declared as number, WHEN: LLM passes "3.14"
        let schema = schema_with_props(
            json!({ "price": { "type": "number" } }),
            &[],
        );
        let result = validate_arguments(&json!({ "price": "3.14" }), &schema);

        assert!(result.is_valid());
        assert_eq!(result.coerced["price"], json!(3.14));
    }

    #[test]
    fn string_true_for_boolean_field_is_coerced() {
        // GIVEN: "spellcheck" declared as boolean, WHEN: LLM passes "true"
        let schema = schema_with_props(
            json!({ "spellcheck": { "type": "boolean" } }),
            &[],
        );
        let result = validate_arguments(&json!({ "spellcheck": "true" }), &schema);

        assert!(result.is_valid());
        assert_eq!(result.coerced["spellcheck"], json!(true));
    }

    #[test]
    fn string_false_for_boolean_field_is_coerced() {
        // GIVEN: "active" declared as boolean, WHEN: LLM passes "false"
        let schema = schema_with_props(
            json!({ "active": { "type": "boolean" } }),
            &[],
        );
        let result = validate_arguments(&json!({ "active": "false" }), &schema);

        assert!(result.is_valid());
        assert_eq!(result.coerced["active"], json!(false));
    }

    #[test]
    fn wrong_type_not_coercible_produces_violation() {
        // GIVEN: "count" declared as integer, WHEN: LLM passes an object
        let schema = schema_with_props(
            json!({ "count": { "type": "integer" } }),
            &[],
        );
        let result = validate_arguments(&json!({ "count": {"nested": true} }), &schema);

        assert!(!result.is_valid());
        assert!(result.violations[0].message.contains("expected integer"));
    }

    #[test]
    fn non_numeric_string_for_integer_field_produces_violation() {
        // GIVEN: "limit" declared as integer, WHEN: LLM passes "hello"
        let schema = schema_with_props(
            json!({ "limit": { "type": "integer" } }),
            &[],
        );
        let result = validate_arguments(&json!({ "limit": "hello" }), &schema);

        assert!(!result.is_valid());
        let msg = &result.violations[0].message;
        assert!(msg.contains("expected integer"), "message: {msg}");
    }

    #[test]
    fn array_field_with_non_array_value_produces_violation() {
        // GIVEN: "tags" declared as array, WHEN: LLM passes a string
        let schema = schema_with_props(
            json!({ "tags": { "type": "array" } }),
            &[],
        );
        let result = validate_arguments(&json!({ "tags": "rust,async" }), &schema);

        assert!(!result.is_valid());
        assert!(result.violations[0].message.contains("expected array"));
    }

    // ── Enum validation ─────────────────────────────────────────────────────

    #[test]
    fn enum_value_valid_passes() {
        // GIVEN: "freshness" with enum [pd, pw, pm], WHEN: "pw" provided
        let schema = schema_with_props(
            json!({ "freshness": { "type": "string", "enum": ["pd", "pw", "pm"] } }),
            &[],
        );
        let result = validate_arguments(&json!({ "freshness": "pw" }), &schema);

        assert!(result.is_valid());
    }

    #[test]
    fn enum_value_invalid_produces_violation() {
        // GIVEN: "safesearch" with enum [off, moderate, strict], WHEN: "none" sent
        let schema = schema_with_props(
            json!({ "safesearch": { "type": "string", "enum": ["off", "moderate", "strict"] } }),
            &[],
        );
        let result = validate_arguments(&json!({ "safesearch": "none" }), &schema);

        assert!(!result.is_valid());
        let msg = &result.violations[0].message;
        assert!(msg.contains("must be one of"), "message: {msg}");
        assert!(msg.contains("\"off\""), "message: {msg}");
    }

    // ── Numeric constraints ─────────────────────────────────────────────────

    #[test]
    fn value_exceeding_maximum_produces_violation() {
        // GIVEN: "count" with maximum 20, WHEN: 100 provided
        let schema = schema_with_props(
            json!({ "count": { "type": "integer", "maximum": 20 } }),
            &[],
        );
        let result = validate_arguments(&json!({ "count": 100 }), &schema);

        assert!(!result.is_valid());
        assert!(result.violations[0].message.contains("<= 20"));
    }

    #[test]
    fn value_at_maximum_passes() {
        // GIVEN: "count" with maximum 20, WHEN: exactly 20 provided
        let schema = schema_with_props(
            json!({ "count": { "type": "integer", "maximum": 20 } }),
            &[],
        );
        let result = validate_arguments(&json!({ "count": 20 }), &schema);

        assert!(result.is_valid());
    }

    #[test]
    fn value_below_minimum_produces_violation() {
        // GIVEN: "offset" with minimum 0, WHEN: -1 provided
        let schema = schema_with_props(
            json!({ "offset": { "type": "integer", "minimum": 0 } }),
            &[],
        );
        let result = validate_arguments(&json!({ "offset": -1 }), &schema);

        assert!(!result.is_valid());
        assert!(result.violations[0].message.contains(">= 0"));
    }

    // ── String constraints ──────────────────────────────────────────────────

    #[test]
    fn string_shorter_than_min_length_produces_violation() {
        // GIVEN: "password" with minLength 8, WHEN: "abc" provided
        let schema = schema_with_props(
            json!({ "password": { "type": "string", "minLength": 8 } }),
            &[],
        );
        let result = validate_arguments(&json!({ "password": "abc" }), &schema);

        assert!(!result.is_valid());
        assert!(result.violations[0].message.contains("at least 8 characters"));
    }

    #[test]
    fn string_longer_than_max_length_produces_violation() {
        // GIVEN: "code" with maxLength 5, WHEN: "toolong" provided
        let schema = schema_with_props(
            json!({ "code": { "type": "string", "maxLength": 5 } }),
            &[],
        );
        let result = validate_arguments(&json!({ "code": "toolong" }), &schema);

        assert!(!result.is_valid());
        assert!(result.violations[0].message.contains("at most 5 characters"));
    }

    // ── No schema / null schema ─────────────────────────────────────────────

    #[test]
    fn null_schema_allows_any_arguments() {
        // GIVEN: null schema (no YAML schema defined)
        let result = validate_arguments(
            &json!({ "anything": "goes", "arbitrary": 42 }),
            &Value::Null,
        );
        assert!(result.is_valid());
    }

    #[test]
    fn schema_without_properties_allows_any_arguments() {
        // GIVEN: schema with only "type: object" and no properties
        let schema = json!({ "type": "object" });
        let result = validate_arguments(&json!({ "foo": "bar" }), &schema);

        assert!(result.is_valid());
    }

    // ── format_error ────────────────────────────────────────────────────────

    #[test]
    fn format_error_includes_violation_messages() {
        // GIVEN: a schema with "query" required
        let schema = schema_with_props(
            json!({ "query": { "type": "string", "description": "Search query" } }),
            &["query"],
        );
        let result = validate_arguments(&json!({}), &schema);

        let error = result.format_error(&schema);
        assert!(error.contains("Tool call validation failed"));
        assert!(error.contains("query"));
        assert!(error.contains("missing"));
    }

    #[test]
    fn format_error_lists_valid_parameters() {
        // GIVEN: schema with known params, WHEN: unknown param sent
        let schema = schema_with_props(
            json!({
                "query": { "type": "string", "description": "Search" },
                "count": { "type": "integer" }
            }),
            &["query"],
        );
        let result = validate_arguments(&json!({ "unknown": "x" }), &schema);

        let error = result.format_error(&schema);
        assert!(error.contains("Valid parameters"), "error: {error}");
        assert!(error.contains("query"), "error: {error}");
        assert!(error.contains("count"), "error: {error}");
    }

    // ── Edge cases ──────────────────────────────────────────────────────────

    #[test]
    fn optional_param_not_provided_is_accepted() {
        // GIVEN: schema with required "query" and optional "count"
        let schema = schema_with_props(
            json!({
                "query": { "type": "string" },
                "count": { "type": "integer" }
            }),
            &["query"],
        );
        let result = validate_arguments(&json!({ "query": "rust" }), &schema);

        assert!(result.is_valid());
    }

    #[test]
    fn null_arguments_treated_as_empty_object() {
        // GIVEN: schema with no required params, WHEN: null arguments
        let schema = schema_with_props(json!({ "query": { "type": "string" } }), &[]);
        let result = validate_arguments(&Value::Null, &schema);

        assert!(result.is_valid());
    }

    #[test]
    fn arguments_not_an_object_produces_violation() {
        // GIVEN: schema, WHEN: arguments is a plain array (invalid)
        let schema = schema_with_props(json!({ "q": { "type": "string" } }), &[]);
        let result = validate_arguments(&json!(["wrong", "type"]), &schema);

        assert!(!result.is_valid());
        assert!(result.violations[0].message.contains("JSON object"));
    }

    #[test]
    fn float_with_zero_fraction_coerced_to_integer() {
        // GIVEN: "count" declared integer, WHEN: 10.0 provided (float with no fractional part)
        let schema = schema_with_props(
            json!({ "count": { "type": "integer" } }),
            &[],
        );
        let result = validate_arguments(&json!({ "count": 10.0 }), &schema);

        assert!(result.is_valid());
        assert_eq!(result.coerced["count"], json!(10));
    }

    #[test]
    fn brave_search_realistic_valid_call() {
        // GIVEN: real brave_search schema, WHEN: valid LLM call
        let schema = json!({
            "type": "object",
            "properties": {
                "query": { "type": "string" },
                "count": { "type": "integer", "maximum": 20 },
                "safesearch": { "type": "string", "enum": ["off", "moderate", "strict"] },
                "freshness": { "type": "string", "enum": ["pd", "pw", "pm", "py"] },
                "spellcheck": { "type": "boolean" }
            },
            "required": ["query"]
        });
        let result = validate_arguments(
            &json!({ "query": "rust async", "count": 5, "safesearch": "moderate" }),
            &schema,
        );
        assert!(result.is_valid());
    }

    #[test]
    fn brave_search_hallucinated_param_rejected() {
        // GIVEN: real brave_search schema, WHEN: LLM adds "language" (not in schema)
        let schema = json!({
            "type": "object",
            "properties": {
                "query": { "type": "string" },
                "count": { "type": "integer" }
            },
            "required": ["query"]
        });
        let result = validate_arguments(
            &json!({ "query": "rust", "language": "en", "format": "json" }),
            &schema,
        );
        assert!(!result.is_valid());
        // Both hallucinated params should appear
        let params: Vec<&str> = result.violations.iter().map(|v| v.param.as_str()).collect();
        assert!(params.contains(&"language"), "params: {params:?}");
        assert!(params.contains(&"format"), "params: {params:?}");
    }

    #[test]
    fn stock_quote_missing_required_symbol() {
        // GIVEN: stock_quote schema requiring "symbol"
        let schema = json!({
            "type": "object",
            "properties": {
                "symbol": { "type": "string" }
            },
            "required": ["symbol"]
        });
        let result = validate_arguments(&json!({}), &schema);

        assert!(!result.is_valid());
        assert_eq!(result.violations[0].param, "symbol");
    }

    #[test]
    fn coerced_args_used_in_valid_result() {
        // GIVEN: integer field with string value that can be coerced
        let schema = schema_with_props(
            json!({
                "query": { "type": "string" },
                "count": { "type": "integer" }
            }),
            &["query"],
        );
        let result =
            validate_arguments(&json!({ "query": "test", "count": "5" }), &schema);

        assert!(result.is_valid());
        // Coerced result must have integer 5, not string "5"
        assert_eq!(result.coerced["query"], json!("test"));
        assert_eq!(result.coerced["count"], json!(5));
    }
}
