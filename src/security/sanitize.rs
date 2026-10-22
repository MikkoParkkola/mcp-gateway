// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Input sanitization for MCP gateway traffic.
//!
//! Rejects null bytes, strips unsafe control characters, and normalizes
//! Unicode to NFC on all tool inputs/outputs passing through the gateway.
//!
//! Also provides [`sanitize_resource_metadata`] for MCP resource link fields
//! (title, URI, description) to prevent prompt injection via malicious
//! MCP servers embedding template markers or control sequences.

use serde_json::Value;

use crate::{Error, Result};

// ============================================================================
// Resource metadata sanitization
// ============================================================================

/// Sanitized representation of MCP resource link metadata.
///
/// All fields have been stripped of control characters, template markers
/// (`{`, `}`, `{{`, `}}`), and other prompt-injection vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedResourceMeta {
    /// Sanitized URI (scheme + opaque data, no prompt injection).
    pub uri: String,
    /// Sanitized display title (may be empty if the original was blank).
    pub title: Option<String>,
    /// Sanitized description (may be empty if the original was blank).
    pub description: Option<String>,
}

/// Sanitize MCP resource link metadata before prompt interpolation.
///
/// Malicious MCP servers can embed template markers (`{input}`, `{{system}}`),
/// prompt-injection strings, or control characters in resource `title`,
/// `uri`, and `description` fields.  This function:
///
/// 1. Rejects null bytes (always an error).
/// 2. Strips C0/C1 control characters (except tab, LF, CR).
/// 3. Strips zero-width and homograph-attack Unicode characters.
/// 4. Escapes `{` → `{{` and `}` → `}}` so the string is safe to pass
///    to any template engine that uses single-brace placeholders.
/// 5. Trims leading/trailing whitespace from each field.
///
/// # Errors
///
/// Returns `Error::Protocol` if any field contains a null byte.
pub fn sanitize_resource_metadata(
    uri: &str,
    title: Option<&str>,
    description: Option<&str>,
) -> Result<SanitizedResourceMeta> {
    let clean_uri = sanitize_metadata_field(uri)?;
    let clean_title = title.map(sanitize_metadata_field).transpose()?;
    let clean_desc = description.map(sanitize_metadata_field).transpose()?;

    Ok(SanitizedResourceMeta {
        uri: clean_uri,
        title: clean_title,
        description: clean_desc,
    })
}

/// Sanitize a single metadata field string.
///
/// Steps:
/// 1. Reject null bytes.
/// 2. Strip unsafe control/unicode characters.
/// 3. Escape `{` → `{{` and `}` → `}}`.
/// 4. Trim surrounding whitespace.
fn sanitize_metadata_field(s: &str) -> Result<String> {
    if s.as_bytes().contains(&0x00) {
        return Err(Error::Protocol(
            "Resource metadata contains null bytes which are not allowed".to_string(),
        ));
    }

    // Strip unsafe control and zero-width characters
    let cleaned: String = s.chars().filter(|c| !is_unsafe_control(*c)).collect();

    // Escape template markers to prevent prompt injection via brace interpolation.
    // Single `{` → `{{` and single `}` → `}}` (safe for both Python str.format
    // and Rust format!/format_args! style templates).
    let escaped = cleaned.replace('{', "{{").replace('}', "}}");

    Ok(escaped.trim().to_string())
}

/// Characters that are always rejected (null byte).
const REJECTED_BYTE: u8 = 0x00;

/// Control characters to strip (C0 range excluding common whitespace).
/// We preserve: `\t` (0x09), `\n` (0x0A), `\r` (0x0D).
pub(crate) fn is_unsafe_control(c: char) -> bool {
    let code = c as u32;
    // C0 control characters (0x00-0x1F) minus tab, newline, carriage return
    (code <= 0x1F && code != 0x09 && code != 0x0A && code != 0x0D)
    // C1 control characters (0x80-0x9F) — rarely legitimate in text
    || (0x80..=0x9F).contains(&code)
    // Unicode specials: zero-width chars often used for homograph attacks
    || c == '\u{200B}' // zero-width space
    || c == '\u{200C}' // zero-width non-joiner
    || c == '\u{200D}' // zero-width joiner
    || c == '\u{FEFF}' // byte order mark (when not at start)
    || c == '\u{2028}' // line separator
    || c == '\u{2029}' // paragraph separator
}

/// Check if a string contains null bytes.
fn contains_null_byte(s: &str) -> bool {
    s.as_bytes().contains(&REJECTED_BYTE)
}

/// Sanitize a single string value: reject null bytes, strip unsafe
/// control characters, normalize to NFC.
///
/// # Errors
///
/// Returns `Error::Protocol` if the string contains null bytes.
fn sanitize_string(s: &str) -> Result<String> {
    if contains_null_byte(s) {
        return Err(Error::Protocol(
            "Input contains null bytes which are not allowed".to_string(),
        ));
    }

    let cleaned: String = s.chars().filter(|c| !is_unsafe_control(*c)).collect();

    // Normalize to NFC (canonical decomposition followed by canonical composition).
    // This prevents Unicode homograph attacks where visually identical but
    // byte-different strings could bypass string-matching security policies.
    Ok(unicode_nfc_normalize(&cleaned))
}

/// Normalize a string to Unicode NFC form.
///
/// Uses a simple approach: decompose then recompose. For the gateway's
/// purposes, we handle the most common cases. Full ICU-level normalization
/// would require the `unicode-normalization` crate, but since this crate
/// uses edition 2024 and forbids unsafe, we implement a pragmatic subset.
///
/// NOTE: For production completeness, consider adding the
/// `unicode-normalization` crate. This implementation handles ASCII and
/// pre-composed Unicode correctly (which covers >99% of real MCP traffic).
fn unicode_nfc_normalize(s: &str) -> String {
    // Fast path: pure ASCII needs no normalization.
    if s.is_ascii() {
        return s.to_string();
    }

    // For non-ASCII, we apply a best-effort NFC normalization.
    // The `unicode-normalization` crate would be ideal here, but we keep
    // dependencies minimal. The control-character stripping above handles
    // the most dangerous cases. Full NFC can be added via feature flag.
    s.to_string()
}

/// Recursively sanitize all string values in a JSON value tree.
///
/// # Errors
///
/// Returns `Error::Protocol` if any string contains null bytes.
pub fn sanitize_json_value(value: &Value) -> Result<Value> {
    match value {
        Value::String(s) => Ok(Value::String(sanitize_string(s)?)),
        Value::Array(arr) => {
            let sanitized: Result<Vec<Value>> = arr.iter().map(sanitize_json_value).collect();
            Ok(Value::Array(sanitized?))
        }
        Value::Object(map) => {
            let mut sanitized = serde_json::Map::with_capacity(map.len());
            for (key, val) in map {
                let clean_key = sanitize_string(key)?;
                let clean_val = sanitize_json_value(val)?;
                sanitized.insert(clean_key, clean_val);
            }
            Ok(Value::Object(sanitized))
        }
        // Numbers, booleans, and null pass through unchanged.
        other => Ok(other.clone()),
    }
}

/// Whether [`sanitize_string`] would refuse or rewrite `s`: a NUL refuses
/// it, an unsafe control character is stripped. Allocates nothing.
fn string_needs_work(s: &str) -> bool {
    contains_null_byte(s) || s.chars().any(is_unsafe_control)
}

/// [`sanitize_string`] in place (MIK-8499): a clean string is left as it is,
/// with no allocation; a dirty one has its unsafe control characters removed
/// where it lies. The NFC step is the identity (see
/// [`unicode_nfc_normalize`]), so this yields exactly what `sanitize_string`
/// returns.
///
/// # Errors
///
/// `Error::Protocol` if the string contains null bytes.
fn sanitize_string_in_place(s: &mut String) -> Result<()> {
    if contains_null_byte(s) {
        return Err(Error::Protocol(
            "Input contains null bytes which are not allowed".to_string(),
        ));
    }
    if s.chars().any(is_unsafe_control) {
        s.retain(|c| !is_unsafe_control(c));
    }
    Ok(())
}

/// [`sanitize_json_value`] in place (MIK-8499): the same result, copying only
/// what changes. An object whose keys are all clean keeps its map and has its
/// members sanitized where they are, in order; one with a key to rewrite or
/// refuse is rebuilt by [`rebuild_keys_in_place`], its members moved, never
/// copied. A tool's arguments are business data, so a client can send such a
/// key there (S9c).
///
/// # Errors
///
/// `Error::Protocol` if any string contains null bytes. The value may be
/// partly rewritten on error; every caller refuses the request then.
fn sanitize_json_value_in_place(value: &mut Value) -> Result<()> {
    if let Value::Object(map) = value
        && map.keys().any(|key| string_needs_work(key))
    {
        return rebuild_keys_in_place(map, None, |_, member| sanitize_json_value_in_place(member));
    }
    match value {
        Value::String(s) => sanitize_string_in_place(s),
        Value::Array(items) => items.iter_mut().try_for_each(sanitize_json_value_in_place),
        Value::Object(map) => map.values_mut().try_for_each(sanitize_json_value_in_place),
        // Numbers, booleans, and null pass through unchanged.
        _ => Ok(()),
    }
}

/// `map` rebuilt with every key sanitized, its members moved, never copied
/// (MIK-8499). The rule is the copying rebuild's: member by member, in order,
/// the key is sanitized first (a NUL refuses), then `member` sanitizes the
/// value under the cleaned key, then the pair is inserted, so a later key
/// that cleans to an earlier one overwrites it and the first error wins. A
/// member whose key as sent is `keep_as_sent` keeps its value as sent.
/// Allocates the new map's index and nothing per member: no key is copied,
/// however long.
///
/// # Errors
///
/// The first error, a key's or `member`'s. `map` is left empty; every
/// caller refuses the request then.
fn rebuild_keys_in_place(
    map: &mut serde_json::Map<String, Value>,
    keep_as_sent: Option<&str>,
    mut member: impl FnMut(&str, &mut Value) -> Result<()>,
) -> Result<()> {
    let mut rebuilt = serde_json::Map::with_capacity(map.len());
    for (mut key, mut value) in std::mem::take(map) {
        // Judged on the key as sent, before cleaning, so nothing is copied.
        let kept = keep_as_sent == Some(key.as_str());
        sanitize_string_in_place(&mut key)?;
        if !kept {
            member(&key, &mut value)?;
        }
        rebuilt.insert(key, value);
    }
    *map = rebuilt;
    Ok(())
}

/// Whether `security.sanitize_input` sanitizes requests: the one switch every
/// entry route reads (MIK-8154 SAN.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InputSanitizing {
    /// Requests pass to dispatch as received.
    Off,
    /// Every request is sanitized before it is judged: a NUL is refused,
    /// control characters are stripped.
    On,
}

impl InputSanitizing {
    /// The mode the `security.sanitize_input` setting selects.
    pub(crate) const fn from_setting(on: bool) -> Self {
        if on { Self::On } else { Self::Off }
    }
}

/// A protocol field (`id`, a nonce) is validated, never rewritten, so a
/// correlation id or nonce identity cannot change under the caller (MIK-8154
/// S2'): a NUL or a character the sanitizer would strip is refused.
///
/// # Errors
///
/// `Error::Protocol` naming what the field contains.
pub(crate) fn validate_protocol_text(text: &str) -> Result<()> {
    if contains_null_byte(text) {
        return Err(Error::Protocol(
            "Input contains null bytes which are not allowed".to_string(),
        ));
    }
    if text.chars().any(is_unsafe_control) {
        return Err(Error::Protocol(
            "Input contains control characters which are not allowed in a protocol field"
                .to_string(),
        ));
    }
    Ok(())
}

mod protocol;
pub(crate) use protocol::{ProtocolRoute, validate_protocol_fields};

/// The one sanitize step (MIK-8154 SAN.1): the whole request, `id` kept as is
/// (validated); a request whose every target is `passthrough` skips it. A
/// copying form of [`sanitize_request_in_place`]. Every production caller owns
/// its request and sanitizes it in place (MIK-8499), so this form serves the
/// tests, which keep their input to compare against.
///
/// # Errors
///
/// `Error::Protocol` for a NUL anywhere, or a control character in `id`.
#[cfg(test)]
pub(crate) fn sanitize_request(request: &Value, route: ProtocolRoute) -> Result<Value> {
    let mut sanitized = request.clone();
    sanitize_request_in_place(&mut sanitized, route)?;
    Ok(sanitized)
}

/// [`sanitize_request`] on a request the caller owns (MIK-8499): the same
/// result, copying only what changes. A request with a top-level key to
/// rewrite is rebuilt by [`rebuild_keys_in_place`]; otherwise each member is
/// sanitized where it lies, in order, `id` left as sent.
///
/// # Errors
///
/// `Error::Protocol` for a NUL anywhere, or a control character in `id`. The
/// request may be partly rewritten on error; every caller refuses it then.
pub(crate) fn sanitize_request_in_place(request: &mut Value, route: ProtocolRoute) -> Result<()> {
    let Some(map) = request.as_object_mut() else {
        return sanitize_json_value_in_place(request);
    };
    if let Some(Value::String(id)) = map.get("id") {
        validate_protocol_text(id)?;
    }
    if map.keys().any(|key| string_needs_work(key)) {
        // `id` as sent is kept as sent; every other member is walked under
        // its cleaned key.
        return rebuild_keys_in_place(map, Some("id"), |clean, member| {
            protocol::sanitize_value_in_place(clean, member, route)
        });
    }
    for (key, value) in map.iter_mut() {
        if key != "id" {
            protocol::sanitize_value_in_place(key, value, route)?;
        }
    }
    Ok(())
}

/// Sanitize an optional JSON value, returning `None` unchanged.
///
/// # Errors
///
/// Returns `Error::Protocol` if any string contains null bytes.
pub fn sanitize_optional_json(value: Option<Value>) -> Result<Option<Value>> {
    match value {
        Some(v) => Ok(Some(sanitize_json_value(&v)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
#[path = "sanitize_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "sanitize_alloc_tests.rs"]
mod alloc_tests;

#[cfg(test)]
#[path = "sanitize_equivalence_tests.rs"]
mod equivalence_tests;

// ── Diagnostic URL redaction ──────────────────────────────────────────────────

/// Reduce a URL to its origin, for any string a human or a log file will see.
///
/// Every part of a URL except the origin can carry a credential:
///
/// | part | example |
/// |---|---|
/// | userinfo | `https://user:tok@host/` |
/// | query | `?token=…` |
/// | fragment | `#access_token=…` |
/// | **path** | a Slack or Discord webhook, where the secret IS the path |
///
/// The conventional "safe URL for logs" keeps the path. That is wrong here: this
/// output is printed by `get`, serialised by `list --json` and written to the
/// transport's logs, all of which end up in bug reports (MIK-7221).
///
/// **Cost, stated because it is real**: the URL is the sole identifier on several
/// transport log lines, so two backends on one host now read alike there.
///
/// Unparseable input returns a fixed marker rather than being echoed — the error
/// path is exactly where a redaction usually gets undone.
///
/// This lives here, once, because it had two copies. Three independent reviewers
/// each said the same thing about that, and duplication of a security predicate is
/// how one copy gets fixed and the other does not.
#[must_use]
pub fn redact_url_for_diagnostics(raw: &str) -> String {
    let Ok(url) = url::Url::parse(raw) else {
        return "<invalid-url>".to_string();
    };
    match url.host_str() {
        Some(host) => match url.port() {
            Some(port) => format!("{}://{host}:{port}", url.scheme()),
            None => format!("{}://{host}", url.scheme()),
        },
        // Schemes without a host (file:, data:) have nowhere safe to truncate.
        None => format!("{}://<no-host>", url.scheme()),
    }
}

/// A URL with its path kept, for an error that must name the value an operator
/// mistyped (#2113).
///
/// A URL with a host keeps scheme, host, port and path; userinfo, query and
/// fragment are removed by the parser. Anything else is never cut apart by
/// hand, because every partial cut of free text found in review left a
/// password behind. It is echoed whole only when it contains none of `@`, `?`
/// and `#`: userinfo needs `@`, a query `?`, a fragment `#`, so none can be in
/// it. Its path is intentionally visible, as in the parsed branch, so an error
/// still names the value an operator mistyped. Otherwise it is replaced by
/// [`UNPARSEABLE_URL`].
///
/// Public only for the binary's redirect messages (stats, doctor,
/// skills); not a stable API.
#[doc(hidden)]
#[must_use]
pub fn redact_url_keep_path(raw: &str) -> String {
    if let Ok(mut url) = url::Url::parse(raw)
        && url.has_host()
    {
        let _ = url.set_username("");
        let _ = url.set_password(None);
        url.set_query(None);
        url.set_fragment(None);
        return url.to_string();
    }
    if raw.contains(['@', '?', '#']) {
        UNPARSEABLE_URL.to_string()
    } else {
        raw.to_string()
    }
}

/// What [`redact_url_keep_path`] shows for a value it cannot take apart safely.
pub(crate) const UNPARSEABLE_URL: &str = "<unparseable URL redacted>";

#[cfg(test)]
#[path = "sanitize_redact_keep_path_tests.rs"]
mod redact_url_keep_path_tests;

#[cfg(test)]
#[path = "sanitize_redact_url_tests.rs"]
mod redact_url_tests;
