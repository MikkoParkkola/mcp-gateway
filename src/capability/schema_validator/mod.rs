// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Strict JSON Schema validator for capability tool arguments and results.
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

use crate::config::InputSchemaEnforcement;
use crate::trust::closed_keys;

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
        self.format_error_with_heading(schema, "Tool call validation failed:")
    }

    /// Format violations into an LLM-friendly error string for output validation.
    #[must_use]
    pub fn format_output_error(&self, schema: &Value) -> String {
        self.format_error_with_heading(schema, "Tool result validation failed:")
    }

    fn format_error_with_heading(&self, schema: &Value, heading: &str) -> String {
        let mut out = String::from(heading);
        out.push_str("\n\n");

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
    // Inputs are strict: an unrecognised parameter is almost always a caller
    // typo or a hallucinated field, so it is reported as a violation.
    validate_arguments_with(arguments, input_schema, InputSchemaEnforcement::Closed)
}

/// Most undeclared-key violations reported in one refusal.
const MAX_KEY_VIOLATIONS: usize = 5;
/// Longest key path echoed back, in characters, before escaping.
const MAX_KEY_PATH_CHARS: usize = 64;
/// Longest MCP refusal text, in bytes.
const MAX_REFUSAL_BYTES: usize = 4096;

/// [`validate_arguments`] under an explicit enforcement mode (MIK-7570.SCHEMA.1).
///
/// Undeclared keys are found at every depth by the schema walker; `off` skips
/// that walk and leaves the type checks. Keys the schema admits beyond its
/// `properties` are carried into `coerced` rather than dropped.
#[must_use]
pub(crate) fn validate_arguments_with(
    arguments: &Value,
    input_schema: &Value,
    mode: InputSchemaEnforcement,
) -> SchemaValidationResult {
    let faults = closed_keys::undeclared_keys(arguments, input_schema, mode);
    if !faults.is_empty() {
        return SchemaValidationResult {
            violations: key_violations(&faults, input_schema),
            coerced: arguments.clone(),
        };
    }
    let mut result = validate_object(arguments, input_schema, false);
    if result.is_valid()
        && let (Value::Object(coerced), Value::Object(original)) = (&mut result.coerced, arguments)
    {
        for (key, value) in original {
            coerced.entry(key.clone()).or_insert_with(|| value.clone());
        }
    }
    result
}

/// The refusal text for undeclared argument keys, or `None` when every key is
/// declared. The MCP-backend gate (MIK-7570.SCHEMA.1): keys only, so a call
/// the backend would accept on types is never refused here on types, and the
/// original arguments, not a coerced copy, are what the caller forwards.
#[must_use]
pub(crate) fn undeclared_key_refusal(
    arguments: &Value,
    input_schema: &Value,
    mode: InputSchemaEnforcement,
) -> Option<String> {
    let faults = closed_keys::undeclared_keys(arguments, input_schema, mode);
    if faults.is_empty() {
        return None;
    }
    let result = SchemaValidationResult {
        violations: key_violations(&faults, input_schema),
        coerced: Value::Null,
    };
    let mut text = result.format_error(input_schema);
    // The footer lists a backend's own parameters; a schema with hundreds of
    // them must not make one refusal a huge payload. The violations come
    // first, so the cut only ever shortens the list.
    if text.len() > MAX_REFUSAL_BYTES {
        let mut cut = MAX_REFUSAL_BYTES;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push_str("\n... (parameter list truncated)");
    }
    Some(text)
}

/// Bounded, escaped violations: at most five, each path cut to 64 characters
/// and escaped so no control character or quote reaches the caller raw.
fn key_violations(faults: &[closed_keys::KeyFault], schema: &Value) -> Vec<ValidationViolation> {
    let known: Vec<&str> = schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|p| p.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let shown = |path: &str| -> String {
        let cut: String = path.chars().take(MAX_KEY_PATH_CHARS).collect();
        cut.escape_debug().to_string()
    };
    let mut out: Vec<_> = faults
        .iter()
        .take(MAX_KEY_VIOLATIONS)
        .map(|fault| match fault {
            // A top-level key names the tool's own parameters; a nested one
            // is left to the footer `format_error` appends.
            closed_keys::KeyFault::Undeclared(path) if !path.contains(['.', '[']) => {
                ValidationViolation::new(
                    shown(path),
                    format!(
                        "unknown parameter — valid parameters are: {}",
                        known.join(", ")
                    ),
                )
            }
            closed_keys::KeyFault::Undeclared(path) => {
                ValidationViolation::new(shown(path), "unknown parameter")
            }
            closed_keys::KeyFault::WrongType(path, ty) => {
                ValidationViolation::new(shown(path), format!("expected {ty}"))
            }
            closed_keys::KeyFault::TooDeep => {
                ValidationViolation::new("", "schema nesting too deep")
            }
            closed_keys::KeyFault::TooComplex => ValidationViolation::new("", "schema too complex"),
        })
        .collect();
    if faults.len() > MAX_KEY_VIOLATIONS {
        let more = faults.len() - MAX_KEY_VIOLATIONS;
        out.push(ValidationViolation::new(
            "",
            format!("{more} more not shown"),
        ));
    }
    out
}

/// Core object validator shared by [`validate_arguments`] and [`validate_output`].
///
/// `reject_extra_keys` controls how keys absent from the schema's `properties`
/// are treated: strict (`true`) for inputs, lenient (`false`) for outputs, where
/// upstream APIs legitimately return extra fields the declared schema does not
/// enumerate (e.g. Brave's `mixed`/`type`, Exa's `costDollars`/`searchTime`).
#[must_use]
fn validate_object(
    arguments: &Value,
    input_schema: &Value,
    reject_extra_keys: bool,
) -> SchemaValidationResult {
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
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
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

    // Step 2 – extra keys not declared in the schema (strict for inputs only).
    for key in arg_map.keys() {
        if reject_extra_keys && !properties.contains_key(key.as_str()) {
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

        let (coerced_value, type_violations) = validate_property(name, raw_value, prop_schema);

        violations.extend(type_violations);
        coerced_map.insert(name.clone(), coerced_value);
    }

    // If there are type violations keep the original args (they'll be rejected).
    let coerced = if violations.is_empty() {
        Value::Object(coerced_map)
    } else {
        arguments.clone()
    };

    SchemaValidationResult {
        violations,
        coerced,
    }
}

/// Validate `result` against `output_schema`.
///
/// This uses the same bounded JSON Schema subset as [`validate_arguments`]:
/// required properties, unknown properties, basic type checks/coercions, enums,
/// and simple numeric/string constraints.
#[must_use]
pub fn validate_output(result: &Value, output_schema: &Value) -> SchemaValidationResult {
    // Outputs fail closed by default: extra keys not declared in the schema are
    // rejected, so a backend cannot smuggle undeclared fields past the contract
    // (anti-exfiltration control). A schema may opt into leniency with
    // `additionalProperties: true` — used for backends like search whose
    // upstream responses carry well-known extra fields the schema does not
    // enumerate (e.g. Brave's `mixed`/`type`, Exa's `costDollars`). Required and
    // type checks always apply.
    let allows_extra = output_schema.get("additionalProperties") == Some(&Value::Bool(true));
    validate_object(result, output_schema, !allows_extra)
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
        if let Some(enum_values) = prop_schema.get("enum").and_then(Value::as_array)
            && !enum_values.contains(&coerced)
        {
            let options: Vec<String> = enum_values.iter().map(value_to_display_string).collect();
            violations.push(ValidationViolation::new(
                name,
                format!("must be one of: {}", options.join(", ")),
            ));
        }

        // Numeric constraints.
        if let Some(num) = coerced.as_f64() {
            if let Some(min) = prop_schema.get("minimum").and_then(Value::as_f64)
                && num < min
            {
                violations.push(ValidationViolation::new(name, format!("must be >= {min}")));
            }
            if let Some(max) = prop_schema.get("maximum").and_then(Value::as_f64)
                && num > max
            {
                violations.push(ValidationViolation::new(name, format!("must be <= {max}")));
            }
        }

        // String length constraints.
        if let Some(s) = coerced.as_str() {
            let len = s.chars().count();
            if let Some(min_len) = prop_schema.get("minLength").and_then(Value::as_u64)
                && (len as u64) < min_len
            {
                violations.push(ValidationViolation::new(
                    name,
                    format!("must be at least {min_len} characters long"),
                ));
            }
            if let Some(max_len) = prop_schema.get("maxLength").and_then(Value::as_u64)
                && (len as u64) > max_len
            {
                violations.push(ValidationViolation::new(
                    name,
                    format!("must be at most {max_len} characters long"),
                ));
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
        _ => Err(format!("expected string, got {}", json_type_name(value))),
    }
}

fn coerce_to_integer(value: &Value) -> Result<Value, String> {
    match value {
        Value::Number(n) if n.is_i64() || n.is_u64() => Ok(value.clone()),
        Value::Number(n) => {
            // Float with no fractional part → integer.
            if let Some(f) = n.as_f64()
                && f.fract() == 0.0
            {
                #[allow(clippy::cast_possible_truncation)]
                return Ok(Value::Number((f as i64).into()));
            }
            Err(format!("expected integer, got float {n}"))
        }
        Value::String(s) => s
            .trim()
            .parse::<i64>()
            .map(|i| Value::Number(i.into()))
            .map_err(|_| {
                format!("expected integer, got string \"{s}\" which is not a valid integer")
            }),
        _ => Err(format!("expected integer, got {}", json_type_name(value))),
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
        _ => Err(format!("expected number, got {}", json_type_name(value))),
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
        _ => Err(format!("expected boolean, got {}", json_type_name(value))),
    }
}

fn coerce_to_array(value: &Value) -> Result<Value, String> {
    match value {
        Value::Array(_) => Ok(value.clone()),
        _ => Err(format!("expected array, got {}", json_type_name(value))),
    }
}

fn coerce_to_object(value: &Value) -> Result<Value, String> {
    match value {
        Value::Object(_) => Ok(value.clone()),
        _ => Err(format!("expected object, got {}", json_type_name(value))),
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
            let ty = prop.get("type").and_then(Value::as_str).unwrap_or("any");
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

            let info = format!(
                "({ty}{req}){enum_hint}{}",
                if desc.is_empty() {
                    String::new()
                } else {
                    format!(" — {desc}")
                }
            );
            (name.clone(), info)
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
