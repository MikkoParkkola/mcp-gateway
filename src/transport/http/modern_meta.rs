// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a 2026-07-28 peer requires of an outbound request: the protocol
//! headers and the `_meta` envelope. Split out of `http/mod.rs` unchanged.

use reqwest::header;
use serde_json::Value;

use crate::protocol::extensions::Extension;
use crate::protocol::meta::{KEY_CLIENT_CAPABILITIES, KEY_PROTOCOL_VERSION, MODERN_VERSIONS};
use crate::{Error, Result};

/// Re-assert on a modern peer's request what the revision requires of it.
///
/// Runs at the LAST writer on each outbound path rather than inside
/// `build_mcp_headers`, and that placement is the point. The builder merges the
/// backend's static headers itself, and the request path merges per-request
/// `extra_headers` *after* the builder returns — so a value written inside the
/// builder is one an operator's configured header silently overrides. These are
/// protocol facts about the dialect being spoken, not defaults an operator gets
/// to disagree with.
///
/// Removing `MCP-Session-Id` is `MIK-7215.STATELESS.3a`: the revision prohibits
/// emitting it, and the prohibition is on emission rather than on minting, so
/// the session a legacy handshake left behind must be dropped here rather than
/// never taken.
///
/// `Mcp-Name` mirrors the body field the *method* selects
/// (`crate::protocol::headers::mcp_name_body_field`), never a search for a
/// plausible field: a `resources/read` carrying a decoy `name` beside the `uri`
/// it actually uses would otherwise be routed on a value the body never agreed
/// to. A method that must carry a name and cannot produce one fails here rather
/// than on the wire — a modern peer rejects it `-32602`, and doing it locally
/// keeps the reason attached to the call that caused it.
pub(super) fn finalise_modern_headers(
    headers: &mut header::HeaderMap,
    method: &str,
    params: Option<&Value>,
) -> Result<()> {
    headers.insert(
        "MCP-Protocol-Version",
        header::HeaderValue::from_static(MODERN_VERSIONS[0]),
    );
    headers.remove("MCP-Session-Id");
    headers.insert(
        "Mcp-Method",
        modern_header_value(method, "Mcp-Method", method)?,
    );

    let Some(field) = crate::protocol::headers::mcp_name_body_field(method) else {
        // Not every method names something. Writing the header anyway would
        // assert a name the body does not have.
        headers.remove("Mcp-Name");
        return Ok(());
    };
    let name = params
        .and_then(|params| params.get(field))
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            // `Protocol`, not `TransportPermanent`: nothing was transported.
            // The caller's own body is malformed, so this maps to -32600
            // (invalid request) and stays out of the backend's failure record.
            Error::Protocol(format!(
                "cannot send `{method}` to a 2026 peer: `Mcp-Name` mirrors \
                 `params.{field}`, which is missing, empty or not a string"
            ))
        })?;
    headers.insert("Mcp-Name", modern_header_value(name, "Mcp-Name", method)?);
    Ok(())
}

/// One header value, encoded so a legal name cannot become an illegal header.
///
/// A tool name is backend-supplied and may hold anything UTF-8 allows, so the
/// value is sentinel-encoded rather than trusted
/// (`crate::protocol::headers::encode_header_value`). The residual failure is
/// unreachable in practice — the encoder's output is visible ASCII — and is
/// returned rather than unwrapped because a panic on the outbound path would
/// take the whole gateway down for one malformed name.
pub(super) fn modern_header_value(
    value: &str,
    header: &'static str,
    method: &str,
) -> Result<header::HeaderValue> {
    header::HeaderValue::from_str(&crate::protocol::headers::encode_header_value(value)).map_err(
        |_| {
            Error::TransportPermanent(format!(
                "cannot send `{method}` to a 2026 peer: `{header}` could not be encoded"
            ))
        },
    )
}

/// Wrap outbound `params` in the `_meta` envelope a modern peer requires.
///
/// Merges rather than replaces: `_meta` is a shared namespace and a caller's
/// own keys (a trace context, say) are not this transport's to discard. The two
/// protocol keys are overwritten because their value is a fact about the
/// dialect, not a caller preference.
///
/// `clientInfo` is deliberately absent. It is optional and self-asserted, so
/// sending one would be an identity claim made by the transport on the
/// gateway's behalf — the ticket's identity criteria decide that, not this.
///
/// Both failures are LOCAL: nothing is sent. A `params` that is not an object,
/// or an `_meta` that is not an object, cannot carry the required keys, and the
/// alternatives are worse than failing — overwriting destroys caller data, and
/// sending unchanged means a real modern peer answers `-32602` after the fact.
pub(crate) fn with_modern_meta(method: &str, params: Option<Value>) -> Result<Option<Value>> {
    let mut params = match params {
        None => serde_json::Map::new(),
        Some(Value::Object(map)) => map,
        Some(other) => {
            return Err(Error::Protocol(format!(
                "cannot send `{method}` to a 2026 peer: `params` must be an object to carry the \
                 required `_meta`, got {kind}",
                kind = value_kind(&other),
            )));
        }
    };

    let meta = match params.remove("_meta") {
        None => serde_json::Map::new(),
        Some(Value::Object(map)) => map,
        Some(other) => {
            return Err(Error::Protocol(format!(
                "cannot send `{method}` to a 2026 peer: `params._meta` must be an object, got \
                 {kind}",
                kind = value_kind(&other),
            )));
        }
    };

    let mut meta = meta;
    meta.insert(
        KEY_PROTOCOL_VERSION.to_string(),
        Value::String(MODERN_VERSIONS[0].to_string()),
    );
    // Matches what the legacy handshake already declares for this client
    // (`"capabilities": {}`), so the two paths cannot disagree about the
    // gateway's own capabilities.
    meta.insert(
        KEY_CLIENT_CAPABILITIES.to_string(),
        Value::Object(serde_json::Map::new()),
    );
    params.insert("_meta".to_string(), Value::Object(meta));
    Ok(Some(Value::Object(params)))
}

/// The methods that may carry the tasks opt-in, and nothing else.
///
/// The opt-in selects task-augmented execution upstream, so the vocabulary it
/// unlocks is exactly the one the adapter implements: the initial submission
/// (`tools/call`), the poll (`tasks/get`), and the one cancel of a handle whose
/// task the owner cancelled (`tasks/cancel`, MIK-7642 design r5 R5.2).
/// `tasks/update` exists upstream and is outside this adapter by construction
/// — an allow-list keeps a future caller from reaching it through this door by
/// passing a method name.
pub(super) const TASK_CAPABILITY_METHODS: [&str; 3] = ["tools/call", "tasks/get", "tasks/cancel"];

/// Build the modern `_meta` envelope, then declare the one tasks extension in it.
///
/// Layered on [`with_modern_meta`] rather than beside it: the protocol version,
/// the params/`_meta` object validation and their two local failures are the
/// same facts here as on any other modern request, and a second copy of them
/// would be a second thing to keep in step. This adds exactly one key —
/// `_meta[clientCapabilities].extensions["io.modelcontextprotocol/tasks"] = {}`
/// — on top of the empty capabilities that path always writes.
///
/// What it does NOT do is preserve a caller's own `extensions`. The declaration
/// is the transport's, about what this gateway implements; forwarding whatever
/// a caller put there would let an upstream select behaviour the gateway has no
/// code to handle, and would make the capability set forgeable from params.
pub(super) fn with_task_capability_meta(
    method: &str,
    params: Option<Value>,
) -> Result<Option<Value>> {
    let params = with_modern_meta(method, params)?;
    let Some(Value::Object(mut params)) = params else {
        // Unreachable: `with_modern_meta` returns `Some(object)` or an error.
        return Err(Error::Protocol(format!(
            "cannot send `{method}` with the tasks capability: modern `_meta` envelope missing"
        )));
    };
    let Some(Value::Object(meta)) = params.get_mut("_meta") else {
        return Err(Error::Protocol(format!(
            "cannot send `{method}` with the tasks capability: modern `_meta` envelope missing"
        )));
    };
    let mut extensions = serde_json::Map::new();
    extensions.insert(
        Extension::Tasks.id().to_string(),
        Value::Object(serde_json::Map::new()),
    );
    let mut capabilities = serde_json::Map::new();
    capabilities.insert("extensions".to_string(), Value::Object(extensions));
    meta.insert(
        KEY_CLIENT_CAPABILITIES.to_string(),
        Value::Object(capabilities),
    );
    Ok(Some(Value::Object(params)))
}

/// The era probe's method, spelled here because `backend::era`'s constant is
/// private to that module. Kept as its own predicate so the two sites that must
/// treat the probe as a pre-handshake message read the same rule.
pub(super) fn is_era_probe(method: &str) -> bool {
    method == "server/discover"
}

/// Name a JSON value's kind for an error a human has to act on.
pub(super) fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

#[cfg(test)]
mod refusal_tests {
    use super::*;

    /// MIK-8195 W1 (`with_modern_meta`, critical d): params that cannot carry
    /// `_meta` are refused before dispatch, naming the method.
    #[test]
    fn non_object_params_are_refused() {
        let err = with_modern_meta("tools/call", Some(serde_json::json!(["a"])))
            .expect_err("an array cannot carry _meta");
        let Error::Protocol(message) = err else {
            panic!("not a protocol refusal");
        };
        assert!(message.contains("`params` must be an object"), "{message}");
        assert!(message.contains("tools/call"), "{message}");
    }

    /// MIK-8195 W1 (`with_modern_meta`, critical d): a caller's non-object
    /// `_meta` is refused rather than overwritten or dropped.
    #[test]
    fn a_non_object_meta_is_refused() {
        let err = with_modern_meta(
            "tools/call",
            Some(serde_json::json!({"name": "x", "_meta": "forged"})),
        )
        .expect_err("a string _meta is refused");
        let Error::Protocol(message) = err else {
            panic!("not a protocol refusal");
        };
        assert!(
            message.contains("`params._meta` must be an object"),
            "{message}"
        );
    }
}
