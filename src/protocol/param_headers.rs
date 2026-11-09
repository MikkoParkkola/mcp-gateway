// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `x-mcp-header` schema validation (MIK-7214.HEADER.7/.8).
//!
//! A backend declares, inside a tool's `inputSchema`, that one property's value
//! must be mirrored onto an `Mcp-Param-{name}` header of the outbound request.
//! The annotation is a **server-side schema declaration**: a caller cannot name
//! a header by sending one, because the name is read from the schema and never
//! from the arguments.
//!
//! Spec: `server/tools.mdx:334-359`.

use serde_json::Value;
use std::collections::HashSet;

/// Maximum nested property-schema depth, with the root at depth zero.
/// Validation and mirroring stop at this depth; deeper levels are ignored.
const MAX_MIRROR_DEPTH: usize = 32;

/// JSON Schema keyword carrying the mirror declaration.
pub const MIRROR_ANNOTATION: &str = "x-mcp-header";

/// Mandatory prefix for every mirrored header name.
pub const PARAM_HEADER_PREFIX: &str = "Mcp-Param-";

/// Largest integer an IEEE-754 double represents exactly (2^53 - 1).
pub const SAFE_INTEGER_MAX: i64 = 9_007_199_254_740_991;

/// A violation of an `x-mcp-header` constraint.
///
/// Any variant excludes the whole tool from `tools/list` (HEADER.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorViolation {
    /// The annotation value is the empty string.
    Empty,
    /// The value is not an RFC 9110 §5.1 field-name token.
    NotToken,
    /// The value carries a control character (CR, LF or other).
    Control,
    /// Two properties declare the same name, compared case-insensitively.
    Duplicate,
    /// The annotated property is not `integer`, `string` or `boolean`.
    UnsupportedType,
    /// The annotation value is not a JSON string.
    NotAString,
    /// An `integer` property declares a `minimum`/`maximum` bound outside the
    /// IEEE-754 safe range.
    IntegerOutOfRange,
}

impl std::fmt::Display for MirrorViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            Self::Empty => "header name is empty",
            Self::NotToken => "header name is not an RFC 9110 field-name token",
            Self::Control => "header name contains a control character",
            Self::Duplicate => "header name is declared twice (case-insensitively)",
            Self::UnsupportedType => "annotated property is not of type integer, string or boolean",
            Self::NotAString => "annotation value is not a string",
            Self::IntegerOutOfRange => {
                "integer property declares a bound outside the IEEE-754 safe range"
            }
        };
        f.write_str(reason)
    }
}

/// One validated mirror declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirroredParam {
    /// Property name inside `inputSchema.properties`.
    pub property: String,
    /// Full outbound header name, already `Mcp-Param-` prefixed.
    pub header_name: String,
}

/// `true` where `c` is an RFC 9110 §5.1 `tchar`.
///
/// Control characters are excluded by construction: none of them is a `tchar`,
/// so [`MirrorViolation::Control`] is reported before this is consulted only to
/// give the operator the specific reason.
fn is_tchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

/// Validates one annotation value against the syntactic constraints.
fn validate_name(value: &Value) -> Result<&str, MirrorViolation> {
    let name = value.as_str().ok_or(MirrorViolation::NotAString)?;
    if name.is_empty() {
        return Err(MirrorViolation::Empty);
    }
    if name.chars().any(char::is_control) {
        return Err(MirrorViolation::Control);
    }
    if !name.chars().all(is_tchar) {
        return Err(MirrorViolation::NotToken);
    }
    Ok(name)
}

/// `true` where the declared JSON Schema type may be mirrored.
///
/// `number` is rejected deliberately: a double has no lossless header rendering
/// (spec `server/tools.mdx:352`).
fn type_is_mirrorable(schema: &Value) -> bool {
    matches!(
        schema.get("type").and_then(Value::as_str),
        Some("integer" | "string" | "boolean")
    )
}

/// Rejects an `integer` property whose schema prescribes a value outside the
/// IEEE-754 safe range, whether as a bound, a `const`, or an `enum` member.
///
/// This is the schema-time half of the safe-range constraint; the per-call half
/// is [`header_value_for`], which drops an out-of-range argument at mirroring
/// time. A schema declaring no bound therefore stays listed, and its arguments
/// are checked one call at a time.
fn bounds_are_safe(schema: &Value) -> bool {
    if schema.get("type").and_then(Value::as_str) != Some("integer") {
        return true;
    }
    let bounds = [
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "const",
    ]
    .iter()
    .filter_map(|key| schema.get(*key));
    let members = schema
        .get("enum")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
        .iter();
    bounds.chain(members).all(is_safe_integer)
}

/// `true` where `value` is not a number, or is an integer an IEEE-754 double
/// represents exactly. A number that is not an `i64` at all (a float, or a
/// `u64` past `i64::MAX`) is out of range by definition.
///
/// The range is tested directly rather than through `abs()`, which panics on
/// `i64::MIN` under overflow checks and wraps to a negative value without them
/// — either way the wrong answer for the one input that most needs the right
/// one.
fn is_safe_integer(value: &Value) -> bool {
    let Some(number) = value.as_number() else {
        return true;
    };
    number
        .as_i64()
        .is_some_and(|v| (-SAFE_INTEGER_MAX..=SAFE_INTEGER_MAX).contains(&v))
}

/// Collects the `x-mcp-header` declarations at one level of `input_schema`.
///
/// Returns the first violation encountered; the caller excludes the tool.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use mcp_gateway::protocol::param_headers::mirrored_params;
///
/// let schema = json!({
///     "type": "object",
///     "properties": { "tenant": { "type": "string", "x-mcp-header": "Tenant" } }
/// });
/// let mirrored = mirrored_params(&schema).unwrap();
/// assert_eq!(mirrored[0].header_name, "Mcp-Param-Tenant");
/// ```
pub fn mirrored_params(input_schema: &Value) -> Result<Vec<MirroredParam>, MirrorViolation> {
    let Some(properties) = input_schema.get("properties").and_then(Value::as_object) else {
        return Ok(Vec::new());
    };

    let mut seen: Vec<String> = Vec::new();
    let mut mirrored = Vec::new();

    for (property, schema) in properties {
        let Some(annotation) = schema.get(MIRROR_ANNOTATION) else {
            continue;
        };
        let name = validate_name(annotation)?;
        if !type_is_mirrorable(schema) {
            return Err(MirrorViolation::UnsupportedType);
        }
        if !bounds_are_safe(schema) {
            return Err(MirrorViolation::IntegerOutOfRange);
        }
        let folded = name.to_ascii_lowercase();
        if seen.contains(&folded) {
            return Err(MirrorViolation::Duplicate);
        }
        seen.push(folded);
        mirrored.push(MirroredParam {
            property: property.clone(),
            header_name: format!("{PARAM_HEADER_PREFIX}{name}"),
        });
    }

    Ok(mirrored)
}

/// Validates declarations through `MAX_MIRROR_DEPTH`, regardless of arguments.
/// Header names must be unique across the visited levels, ignoring ASCII case.
/// The root is depth zero; deeper levels are neither validated nor mirrored,
/// and exceeding the depth bound is not a violation.
pub(crate) fn validate_mirrors(input_schema: &Value) -> Result<(), MirrorViolation> {
    validate_mirror_level(input_schema, 0, &mut HashSet::new())
}

fn validate_mirror_level(
    schema: &Value,
    depth: usize,
    seen: &mut HashSet<String>,
) -> Result<(), MirrorViolation> {
    if depth > MAX_MIRROR_DEPTH {
        return Ok(());
    }
    for param in mirrored_params(schema)? {
        if !seen.insert(param.header_name.to_ascii_lowercase()) {
            return Err(MirrorViolation::Duplicate);
        }
    }
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for property in properties.values() {
            if property.get("properties").is_some() {
                validate_mirror_level(property, depth + 1, seen)?;
            }
        }
    }
    Ok(())
}

/// Renders one argument as a header value, or `None` where it cannot be
/// mirrored losslessly (HEADER.5).
///
/// This is the per-call half of the safe-range constraint whose schema-time
/// half is [`bounds_are_safe`]: an argument outside the IEEE-754 exact range is
/// dropped rather than mirrored as a number the peer would read back
/// differently. Strings, including control characters, are preserved here
/// and encoded before being emitted as header values.
fn header_value_for(argument: &Value) -> Option<String> {
    match argument {
        Value::String(text) => Some(text.clone()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Number(number) => {
            let value = number.as_i64()?;
            (-SAFE_INTEGER_MAX..=SAFE_INTEGER_MAX)
                .contains(&value)
                .then(|| value.to_string())
        }
        _ => None,
    }
}

/// `true` where `name` sits in the gateway-owned `Mcp-Param-` namespace,
/// compared case-insensitively as HTTP field names are.
#[must_use]
pub fn is_param_header(name: &str) -> bool {
    let prefix = PARAM_HEADER_PREFIX.as_bytes();
    let name = name.as_bytes();
    name.len() >= prefix.len() && name[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// The `Mcp-Param-*` headers one `tools/call` must carry, derived from the
/// tool's own `inputSchema` and that call's arguments (HEADER.5).
///
/// Traversal and validation cover `properties` through `MAX_MIRROR_DEPTH`,
/// with the root at depth zero. Deeper levels are neither validated nor mirrored;
/// exceeding the depth bound is not a violation.
/// Validation is independent of arguments: a violation within the visited levels,
/// including a duplicate header name across levels, mirrors nothing.
/// Such a tool is also excluded from `tools/list`.
///
/// Empty strings are emitted unchanged. Every other value passes through the
/// shared encoder, preserving spaces, non-ASCII text and control characters.
#[must_use]
pub fn mirror_headers(input_schema: &Value, arguments: &Value) -> Vec<(String, String)> {
    if validate_mirrors(input_schema).is_err() {
        return Vec::new();
    }
    let mut out = Vec::new();
    collect_mirrors(input_schema, arguments, 0, &mut out);
    out
}

fn collect_mirrors(
    schema: &Value,
    arguments: &Value,
    depth: usize,
    out: &mut Vec<(String, String)>,
) {
    if depth > MAX_MIRROR_DEPTH {
        return;
    }
    if let Ok(declared) = mirrored_params(schema) {
        for param in declared {
            if let Some(value) = arguments.get(&param.property).and_then(header_value_for) {
                let value = if value.is_empty() {
                    value
                } else {
                    crate::protocol::headers::encode_header_value(&value)
                };
                out.push((param.header_name, value));
            }
        }
    }
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return;
    };
    for (name, property) in properties {
        if property.get("properties").is_none() {
            continue;
        }
        if let Some(nested) = arguments.get(name).filter(|value| value.is_object()) {
            collect_mirrors(property, nested, depth + 1, out);
        }
    }
}
