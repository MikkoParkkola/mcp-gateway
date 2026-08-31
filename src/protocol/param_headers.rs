// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `x-mcp-header` argument mirroring (MIK-7214.HEADER.5/.7/.8).
//!
//! A backend declares, inside a tool's `inputSchema`, that one property's value
//! must be mirrored onto an `Mcp-Param-{name}` header of the outbound request.
//! The annotation is a **server-side schema declaration**: a caller cannot name
//! a header by sending one, because the name is read from the schema and never
//! from the arguments.
//!
//! Spec: `server/tools.mdx:334-359`.

use serde_json::Value;

/// JSON Schema keyword carrying the mirror declaration.
pub const MIRROR_ANNOTATION: &str = "x-mcp-header";

/// Mandatory prefix for every mirrored header name.
pub const PARAM_HEADER_PREFIX: &str = "Mcp-Param-";

/// Largest integer an IEEE-754 double represents exactly (2^53 - 1).
pub const SAFE_INTEGER_MAX: i64 = 9_007_199_254_740_991;

/// A violation of one of the six `x-mcp-header` constraints.
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

/// Collects every `x-mcp-header` declaration in `input_schema`.
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

/// Renders one argument value as a header value, or `None` where it cannot be
/// mirrored losslessly.
///
/// An integer outside the IEEE-754 safe range is a **per-call** omission, not a
/// tool exclusion: the schema was valid, this one argument is not.
pub fn header_value_for(argument: &Value) -> Option<String> {
    match argument {
        Value::String(s) if !s.chars().any(char::is_control) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => {
            let i = n.as_i64()?;
            (i.abs() <= SAFE_INTEGER_MAX).then(|| i.to_string())
        }
        _ => None,
    }
}

/// `true` where a mirrored header name must be dropped before it reaches the
/// wire.
///
/// The mandatory `Mcp-Param-` prefix already makes a collision with a
/// gateway-owned header unconstructible. This is defence in depth against a
/// future edit that loses the prefix, so `Mcp-Param-*` is carved out
/// explicitly — without the carve-out the `Mcp-*` rule would drop every
/// mirrored header.
pub fn is_reserved_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("mcp-param-") {
        return false;
    }
    lower.starts_with("mcp-")
        || matches!(
            lower.as_str(),
            "authorization"
                | "host"
                | "cookie"
                | "connection"
                | "content-length"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
        )
}
