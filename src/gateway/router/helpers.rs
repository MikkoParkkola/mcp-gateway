// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Pure utility functions shared by router handlers.

use crate::error::rpc_codes::{INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST, PARSE_ERROR};
use crate::gateway::health_metrics::{Origin, RpcError};
use crate::gateway::meta_mcp::invoke::egress::Egressed;
use axum::{
    Json,
    http::{HeaderValue, StatusCode},
    response::IntoResponse,
};
use serde::Serialize;
use serde_json::Value;
use tracing::warn;

use crate::protocol::{
    ElicitationCreateParams, JsonRpcResponse, RequestId, SamplingCreateMessageParams,
};

fn build_session_response<T>(
    body: T,
    session_id: &str,
    status: StatusCode,
) -> axum::response::Response
where
    T: Serialize,
{
    let mut resp = Json(body).into_response();
    attach_session_header(resp.headers_mut(), session_id);

    (status, resp).into_response()
}

pub(crate) fn attach_session_header(headers: &mut axum::http::HeaderMap, session_id: &str) {
    // An empty id means the caller has no session, which after MCP 2026-07-28
    // is the ordinary case rather than an error. Emitting the header with an
    // empty value would be worse than omitting it: a client and an intermediary
    // would both read a session that does not exist.
    if session_id.is_empty() {
        return;
    }
    match HeaderValue::from_str(session_id) {
        Ok(value) => {
            headers.insert(
                axum::http::header::HeaderName::from_static("mcp-session-id"),
                value,
            );
        }
        Err(err) => {
            // Unreachable for gateway sessions: every id is a minted `gw-<uuid>`,
            // always a valid header value. Fingerprinted all the same (F9).
            let session_id = crate::gateway::session_id::session_fp(session_id);
            warn!(%session_id, %err, "failed to set mcp-session-id response header");
        }
    }
}

/// The firewall whose tenant guard judges this router's frames
/// (MIK-7116.MIN.2); it shares the process read history with the Meta-MCP's.
pub(crate) fn read_guard(
    state: &super::AppState,
) -> Option<std::sync::Arc<crate::gateway::outbound::Guard>> {
    #[cfg(feature = "firewall")]
    {
        state.firewall.clone()
    }
    #[cfg(not(feature = "firewall"))]
    {
        let _ = state;
        None
    }
}

/// Build an HTTP response with a `mcp-session-id` header from an arbitrary JSON body.
#[cfg(test)] // its last production caller became bodiless (MIK-7759)
pub(super) fn build_json_response(
    body: Value,
    session_id: &str,
    status: StatusCode,
) -> axum::response::Response {
    build_session_response(body, session_id, status)
}

/// The JSON-RPC error an HTTP error response was built from, kept beside it so
/// the `/mcp` exit that returns it unrendered can record its delivery
/// (`judged_answer::record_error_exit`), under the trace of the record that
/// refused it.
#[derive(Clone)]
pub(super) struct ErrorFrame {
    pub(super) frame: JsonRpcResponse,
    pub(super) trace: Option<String>,
}

/// Name the trace `response`'s refusal was recorded under, so its delivery
/// record joins that record.
pub(super) fn trace_error_frame(response: &mut axum::response::Response, trace: String) {
    if let Some(frame) = response.extensions_mut().get_mut::<ErrorFrame>() {
        frame.trace = Some(trace);
    }
}

/// Build an HTTP response with a `mcp-session-id` header and a given status.
pub(super) fn build_response(
    rpc: JsonRpcResponse,
    session_id: &str,
    status: StatusCode,
) -> axum::response::Response {
    // One of the three places a typed frame becomes the HTTP response, so the
    // error count reads its code here and never from a body.
    let marker = RpcError::of_frame(&rpc);
    let frame = rpc.error.is_some().then(|| ErrorFrame {
        frame: rpc.clone(),
        trace: crate::gateway::trace::current(),
    });
    let mut response = build_session_response(rpc, session_id, status);
    if let Some(marker) = marker {
        response.extensions_mut().insert(marker);
    }
    if let Some(frame) = frame {
        response.extensions_mut().insert(frame);
    }
    response
}

/// Build a JSON-RPC error response with a `mcp-session-id` header and status.
pub(super) fn build_error_response(
    id: Option<RequestId>,
    code: i32,
    message: impl Into<String>,
    session_id: &str,
    status: StatusCode,
) -> axum::response::Response {
    build_response(
        JsonRpcResponse::error(id, code, message.into()),
        session_id,
        status,
    )
}

/// Build a JSON-RPC error carrying a `data` payload the client must act on.
///
/// Separate from [`build_error_response`] rather than an `Option` parameter on
/// it: every existing caller would have to name a payload it does not have, and
/// a `None` threaded through forty call sites is how the payload ends up
/// omitted at the one site that needed it.
pub(super) fn build_error_response_with_data(
    id: Option<RequestId>,
    code: i32,
    message: impl Into<String>,
    data: serde_json::Value,
    session_id: &str,
    status: StatusCode,
) -> axum::response::Response {
    build_response(
        JsonRpcResponse::error_with_data(id, code, message.into(), data),
        session_id,
        status,
    )
}

/// The refusal of a request whose new provisional session would pass the cap
/// (MIK-8504): JSON-RPC -32603 with `data.reason` `session_capacity`, HTTP 503,
/// and a `Retry-After` of the provisional idle limit, when slots free up. It is
/// answered before anything runs.
pub(super) fn session_capacity_refusal(id: Option<RequestId>) -> axum::response::Response {
    let mut response = build_error_response_with_data(
        id,
        INTERNAL_ERROR,
        "session capacity reached; retry later",
        serde_json::json!({"reason": "session_capacity"}),
        "",
        StatusCode::SERVICE_UNAVAILABLE,
    );
    let retry = crate::gateway::streaming::PROVISIONAL_SESSION_TTL.as_secs();
    response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from(retry),
    );
    response
}

/// A direct-route answer before it leaves: status and JSON-RPC body, and who
/// wrote the frame it was made from. The direct route takes the answer apart
/// and rebuilds it through `outbound::answer_value`, so `origin` rides along
/// for that call to keep the frame's origin; the error count is marked where
/// the rebuilt frame becomes the response, not here.
#[derive(Debug)]
pub(crate) struct RpcHttp {
    pub(crate) status: StatusCode,
    pub(crate) body: Json<Value>,
    pub(crate) origin: Origin,
    /// The failure the answer carries folded into a tool result, from its
    /// frame (`wire_meta.folded`).
    pub(crate) folded: Option<RpcError>,
}

impl RpcHttp {
    /// An answer the gateway wrote.
    pub(crate) fn gateway(status: StatusCode, body: Value) -> Self {
        Self {
            status,
            body: Json(body),
            origin: Origin::Gateway,
            folded: None,
        }
    }
}

/// A bare status and body is the gateway's own answer.
impl From<(StatusCode, Json<Value>)> for RpcHttp {
    fn from((status, body): (StatusCode, Json<Value>)) -> Self {
        Self {
            status,
            body,
            origin: Origin::Gateway,
            folded: None,
        }
    }
}

impl IntoResponse for RpcHttp {
    fn into_response(self) -> axum::response::Response {
        let marker = RpcError::of_value(&self.body.0, self.origin, self.folded);
        let mut response = (self.status, self.body).into_response();
        if let Some(marker) = marker {
            response.extensions_mut().insert(marker);
        }
        response
    }
}

/// Build a JSON-RPC HTTP response body without attaching a session header.
/// The origin is the frame's own: a backend's answer stays a backend's.
///
/// `to_value_lossy` drops the frame's refusal marker, so a refusal frame raises
/// `Refused` here first. Only refusal frames raise, and only the direct route
/// builds them through this function, so a route with no delivery cell never
/// raises.
pub(super) fn build_http_response(rpc: &Egressed, status: StatusCode) -> RpcHttp {
    let frame = rpc.frame();
    if frame.wire_meta.delivery_refusal {
        crate::gateway::delivery_facts::raise(
            crate::gateway::delivery_facts::ResponseEffect::Refused,
        );
    }
    RpcHttp {
        status,
        body: Json(frame.to_value_lossy()),
        origin: frame.wire_meta.origin,
        folded: frame.wire_meta.folded,
    }
}

/// Count one HTTP request for U1 (MIK-7211), on both routes alike. `false`
/// means this gateway's window segment has sealed: the caller refuses the
/// request unserved ([`window_sealed_response`]), so every served request is
/// in the sealed counts.
pub(super) fn observe_http(
    request: &Value,
    params: Option<&Value>,
    method: &str,
    headers: &axum::http::HeaderMap,
    session_id: Option<&str>,
    sealed: &std::sync::atomic::AtomicBool,
) -> bool {
    let header = |name| headers.get(name).and_then(|value| value.to_str().ok());
    crate::protocol_revision_telemetry::observe_inbound_request_from(
        request,
        params,
        method,
        header(axum::http::HeaderName::from_static("mcp-protocol-version")),
        session_id,
        crate::protocol_revision_telemetry::Transport::Http,
        Some(crate::protocol_revision_telemetry::HttpCaller {
            user_agent: header(axum::http::header::USER_AGENT),
            sealed,
        }),
    )
}

/// The refusal for a request that reaches its count point after this gateway's
/// U1 window segment sealed (MIK-7211): it is neither counted nor served, so
/// the client retries against the next process. It answers with the request's
/// own id, so a client waiting on that id sees the refusal, not a timeout.
pub(super) fn window_sealed_response(request: &Value) -> RpcHttp {
    build_http_error_response(
        request
            .get("id")
            .and_then(|id| serde_json::from_value(id.clone()).ok()),
        -32000,
        "U1 window sealed: this gateway is shutting down; retry",
        StatusCode::SERVICE_UNAVAILABLE,
    )
}

/// Build a JSON-RPC HTTP error body without attaching a session header.
pub(super) fn build_http_error_response(
    id: Option<RequestId>,
    code: i32,
    message: impl Into<String>,
    status: StatusCode,
) -> RpcHttp {
    let frame = JsonRpcResponse::error(id, code, message.into());
    build_http_response(&Egressed::gateway_own(frame), status)
}

/// Build a bodiless `202 Accepted` with the session header. Streamable HTTP
/// (2025-06-18, 2025-11-25): an accepted notification or client response gets
/// 202 with no body (MIK-7759).
pub(super) fn build_accepted_response(session_id: &str) -> axum::response::Response {
    let mut response = StatusCode::ACCEPTED.into_response();
    attach_session_header(response.headers_mut(), session_id);
    response
}

/// The direct `/mcp/{name}` answer on the wire. Its 202 is only ever an
/// accepted notification, whose placeholder body the audit layer has already
/// read; the spec gives it no body (MIK-7759).
pub(super) fn bodiless_accepted(answer: RpcHttp) -> axum::response::Response {
    if answer.status == StatusCode::ACCEPTED {
        return StatusCode::ACCEPTED.into_response();
    }
    answer.into_response()
}

/// Parse `sampling/createMessage` params from raw JSON, returning an early
/// HTTP error response on failure.
#[allow(clippy::result_large_err)] // early-return pattern mirrors existing handlers
pub(super) fn parse_sampling_params(
    id: RequestId,
    params: Option<Value>,
    session_id: &str,
) -> Result<SamplingCreateMessageParams, axum::response::Response> {
    let Some(p) = params else {
        return Err(build_response(
            JsonRpcResponse::error(Some(id), INVALID_PARAMS, "Missing sampling params"),
            session_id,
            StatusCode::BAD_REQUEST,
        ));
    };
    serde_json::from_value(p).map_err(|e| {
        build_response(
            JsonRpcResponse::error(
                Some(id),
                INVALID_PARAMS,
                format!("Invalid sampling params: {e}"),
            ),
            session_id,
            StatusCode::BAD_REQUEST,
        )
    })
}

/// Parse `elicitation/create` params from raw JSON, returning an early HTTP
/// error response on failure.
#[allow(clippy::result_large_err)] // early-return pattern mirrors existing handlers
pub(super) fn parse_elicitation_params(
    id: RequestId,
    params: Option<Value>,
    session_id: &str,
) -> Result<ElicitationCreateParams, axum::response::Response> {
    let Some(p) = params else {
        return Err(build_response(
            JsonRpcResponse::error(Some(id), INVALID_PARAMS, "Missing elicitation params"),
            session_id,
            StatusCode::BAD_REQUEST,
        ));
    };

    serde_json::from_value(p).map_err(|e| {
        build_response(
            JsonRpcResponse::error(
                Some(id),
                INVALID_PARAMS,
                format!("Invalid elicitation params: {e}"),
            ),
            session_id,
            StatusCode::BAD_REQUEST,
        )
    })
}

/// Extract a `RequestId` from a JSON value.
///
/// Supports string and integer ID values per JSON-RPC 2.0 spec.
/// Returns `None` if the value is not a recognised ID type.
pub(crate) fn extract_request_id(value: &Value) -> Option<RequestId> {
    if value.is_string() {
        Some(RequestId::String(value.as_str().unwrap().to_string()))
    } else if value.is_i64() {
        Some(RequestId::Number(value.as_i64().unwrap()))
    } else {
        // An unsigned id above `i64::MAX` lands here too: it cannot be held,
        // so it is unrecognised, never wrapped into a different, negative id
        // that would answer some other request (MIK-8189).
        None
    }
}

/// Check whether a method name represents a notification (no response expected).
pub(crate) fn is_notification_method(method: &str) -> bool {
    method.starts_with("notifications/")
}

/// Extract the `tools/call` parameters (tool name and arguments) from request params.
///
/// Returns `("", {})` when the expected fields are absent so callers never
/// need to deal with `Option`.
// MIK-8014: no request path takes the owned form any more; the tests keep it
// as the reference for what the borrowed form selects.
#[cfg(test)]
pub(crate) fn extract_tools_call_params(params: Option<&Value>) -> (&str, Value) {
    let (tool_name, arguments) = extract_tools_call_params_ref(params);
    (
        tool_name,
        arguments.cloned().unwrap_or_else(|| serde_json::json!({})),
    )
}

/// Borrowed form of [`extract_tools_call_params`]: same field selection, no
/// copy of `arguments`.
///
/// `None` arguments means absent; the owned wrapper is what substitutes the
/// empty object, so a caller that refuses the request never materialises the
/// payload.
pub(crate) fn extract_tools_call_params_ref(params: Option<&Value>) -> (&str, Option<&Value>) {
    let tool_name = params
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let arguments = params.and_then(|p| p.get("arguments"));
    (tool_name, arguments)
}

/// Carry the client's `params._meta` into a meta-tool's `arguments`.
///
/// A conforming client places `_meta` as a sibling of `arguments` inside
/// `params` (`src/protocol/meta.rs`), and `extract_tools_call_params` returns
/// `arguments` alone, so nothing downstream of the router could ever see it.
/// The meta layer reads it off the argument object it is handed, which is why
/// it has to travel there.
///
/// Conditional on purpose. `route_direct_backend_call` runs before the
/// meta-tool match, so an unconditional merge would synthesise a `_meta` key
/// into every direct-route backend payload — inventing a field for backends
/// that never asked for one. Callers pass `is_meta_tool`, and the direct route
/// stays byte-identical.
///
/// An `arguments._meta` the client wrote itself is left alone: the caller's own
/// value is the more specific one, and overwriting it would silently discard it.
pub(crate) fn merge_client_meta(
    arguments: Value,
    params: Option<&Value>,
    is_meta_tool: bool,
) -> Value {
    // Asked before the copy, not after: a caller that already wrote its own
    // `arguments._meta` keeps it, and the metadata it did not need is never
    // copied to be dropped. `entry().or_insert_with` used to give that for
    // free, and moving the insertion out of this function would have lost it.
    if !client_meta_insert_required(Some(&arguments), params, is_meta_tool) {
        return arguments;
    }
    let Some(meta) = params.and_then(|p| p.get("_meta")) else {
        return arguments;
    };
    insert_client_meta(arguments, meta.clone())
}

/// Insertion step of [`merge_client_meta`] over values the caller already owns.
///
/// Split out so a caller that owns the request tree can hand over the `_meta`
/// subtree itself instead of a copy of it: the metadata is as unbounded as the
/// payload, and a merge that moved the arguments but copied the metadata would
/// have traded one payload-sized allocation for another.
///
/// `or_insert` and not `insert`: an `arguments._meta` the client wrote itself
/// wins, present-but-null included, which is the rule the borrowed predicate
/// below reads with `contains_key`. Non-object arguments are returned untouched,
/// exactly as the merge leaves them.
pub(crate) fn insert_client_meta(arguments: Value, meta: Value) -> Value {
    let mut arguments = arguments;
    let Some(map) = arguments.as_object_mut() else {
        return arguments;
    };
    map.entry("_meta").or_insert(meta);
    arguments
}

/// Whether [`merge_client_meta`] would insert a `_meta` into these arguments.
///
/// The single definition of the merge's precondition, decided from borrowed
/// views alone so a caller can find out before it owns anything. The four cases
/// the merge returns its input untouched — not a meta tool, no `params._meta` to
/// carry, arguments that are not an object, and arguments that already carry a
/// `_meta` — answer `false` here.
///
/// `None` arguments means absent, which the merge sees as the substituted empty
/// object: an object with no `_meta`, so the answer is `true` and an absent
/// `arguments` still receives the client's metadata.
pub(crate) fn client_meta_insert_required(
    arguments: Option<&Value>,
    params: Option<&Value>,
    is_meta_tool: bool,
) -> bool {
    if !is_meta_tool {
        return false;
    }
    if params.and_then(|p| p.get("_meta")).is_none() {
        return false;
    }
    match arguments {
        None => true,
        Some(arguments) => arguments
            .as_object()
            .is_some_and(|map| !map.contains_key("_meta")),
    }
}

/// Borrowed form of [`merge_client_meta`]: same result, no copy when the merge
/// would have inserted nothing.
///
/// The four cases the owned merge returns its input untouched — not a meta
/// tool, no `params._meta` to carry, arguments that are not an object, and
/// arguments the client already gave a `_meta` — are exactly the cases where a
/// copy buys nothing, so each returns an alias. [`client_meta_insert_required`]
/// decides them, and the same predicate decides them for a caller that owns the
/// request tree, so the alias case and the ownership case cannot drift apart.
///
/// The insertion case still delegates to [`merge_client_meta`] on a clone, so
/// there is one definition of the merge semantics rather than two. That copy
/// remains for callers holding only a borrow of someone else's arguments; a
/// caller that owns the tree asks the predicate first and moves the subtrees in
/// through [`insert_client_meta`] instead.
pub(crate) fn merge_client_meta_ref<'a>(
    arguments: &'a Value,
    params: Option<&Value>,
    is_meta_tool: bool,
) -> std::borrow::Cow<'a, Value> {
    if !client_meta_insert_required(Some(arguments), params, is_meta_tool) {
        return std::borrow::Cow::Borrowed(arguments);
    }
    std::borrow::Cow::Owned(merge_client_meta(arguments.clone(), params, is_meta_tool))
}

/// [`merge_client_meta`] done in place on a request the caller owns
/// (MIK-8499): the meta tool's own `arguments` gain the client's
/// `params._meta`, so a later [`merge_client_meta_ref`] on them borrows
/// instead of copying the whole argument tree. [`client_meta_insert_required`]
/// decides both, so they cannot drift. Only arguments the client sent are
/// touched; with none, the merge copies an empty object. `_meta` itself is
/// still copied once, as the merge copies it.
pub(crate) fn move_client_meta_into_arguments(
    request: &mut Value,
    is_meta_tool: impl Fn(&str) -> bool,
) {
    if request.get("method").and_then(Value::as_str) != Some("tools/call") {
        return;
    }
    let Some(params) = request.get_mut("params") else {
        return;
    };
    let meta_tool = params
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(&is_meta_tool);
    if !client_meta_insert_required(params.get("arguments"), Some(params), meta_tool)
        || params.get("arguments").is_none()
    {
        return;
    }
    let Some(client_meta) = params.get("_meta").cloned() else {
        return;
    };
    if let Some(arguments) = params.get_mut("arguments") {
        *arguments = insert_client_meta(std::mem::take(arguments), client_meta);
    }
}

/// Parse JSON-RPC request or notification.
///
/// Returns `(Option<RequestId>, method, params)` where `id` is `None` for
/// notifications without request IDs.
#[allow(clippy::result_large_err)] // JsonRpcResponse used directly as HTTP/server error body
pub(crate) fn parse_request(
    value: &Value,
) -> Result<(Option<RequestId>, String, Option<Value>), JsonRpcResponse> {
    let (id, method, params) = parse_request_ref(value)?;
    Ok((id, method.to_string(), params.cloned()))
}

/// Borrowed form of [`parse_request`]: identical validation and identical
/// errors, but `method` and `params` are views into `value`.
///
/// The owned wrapper above is the only thing that copies, so a caller that
/// refuses a request can decide on it without duplicating its payload.
#[allow(clippy::result_large_err)] // mirrors `parse_request`
pub(crate) fn parse_request_ref(
    value: &Value,
) -> Result<(Option<RequestId>, &str, Option<&Value>), JsonRpcResponse> {
    // Check jsonrpc version
    let jsonrpc = value.get("jsonrpc").and_then(|v| v.as_str());
    if jsonrpc != Some("2.0") {
        return Err(JsonRpcResponse::error(
            None,
            INVALID_REQUEST,
            "Invalid JSON-RPC version",
        ));
    }

    // Get ID (required for requests, missing for notifications)
    let id = value.get("id").and_then(extract_request_id);

    // Get method
    let method = value
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcResponse::error(id.clone(), INVALID_REQUEST, "Missing method"))?;

    // Get params (optional)
    let params = value.get("params");

    // For notifications (methods starting with "notifications/"), id is optional
    // For requests, id is required
    if !is_notification_method(method) && id.is_none() {
        return Err(JsonRpcResponse::error(None, INVALID_REQUEST, "Missing id"));
    }

    Ok((id, method, params))
}

#[cfg(test)]
#[path = "merge_client_meta_borrow_tests.rs"]
mod merge_client_meta_borrow_tests;

/// Buffer a request body under the router's `DefaultBodyLimit`, which carries
/// the startup `server.max_body_size`.
///
/// An oversize body is HTTP 413, as on every extractor route; any other read
/// failure stays 400 with JSON-RPC -32700.
pub(super) async fn read_body(
    request: axum::extract::Request,
) -> Result<axum::body::Bytes, RpcHttp> {
    use axum::extract::FromRequest as _;
    axum::body::Bytes::from_request(request, &())
        .await
        .map_err(|rejection| {
            if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                build_http_error_response(
                    None,
                    INVALID_REQUEST,
                    "Request body exceeds server.max_body_size",
                    StatusCode::PAYLOAD_TOO_LARGE,
                )
            } else {
                build_http_error_response(
                    None,
                    PARSE_ERROR,
                    format!("Failed to read body: {}", rejection.body_text()),
                    StatusCode::BAD_REQUEST,
                )
            }
        })
}
