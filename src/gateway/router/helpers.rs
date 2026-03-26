//! Pure utility functions shared by router handlers.

use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::{Value, json};

use crate::protocol::{JsonRpcResponse, RequestId, SamplingCreateMessageParams};

/// Build an HTTP response with a `mcp-session-id` header from an arbitrary JSON body.
pub(super) fn build_json_response(
    body: Value,
    session_id: &str,
    status: StatusCode,
) -> axum::response::Response {
    let mut resp = Json(body).into_response();
    resp.headers_mut().insert(
        axum::http::header::HeaderName::from_static("mcp-session-id"),
        session_id.parse().unwrap(),
    );
    (status, resp).into_response()
}

/// Build an HTTP response with a `mcp-session-id` header and a given status.
pub(super) fn build_response(
    rpc: JsonRpcResponse,
    session_id: &str,
    status: StatusCode,
) -> axum::response::Response {
    build_json_response(serde_json::to_value(rpc).unwrap(), session_id, status)
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

/// Build a `202 Accepted` response with an empty JSON body and session header.
pub(super) fn build_accepted_response(session_id: &str) -> axum::response::Response {
    build_json_response(json!({}), session_id, StatusCode::ACCEPTED)
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
            JsonRpcResponse::error(Some(id), -32602, "Missing sampling params"),
            session_id,
            StatusCode::BAD_REQUEST,
        ));
    };
    serde_json::from_value(p).map_err(|e| {
        build_response(
            JsonRpcResponse::error(Some(id), -32602, format!("Invalid sampling params: {e}")),
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
    } else if value.is_u64() {
        #[allow(clippy::cast_possible_wrap)]
        Some(RequestId::Number(value.as_u64().unwrap() as i64))
    } else {
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
pub(crate) fn extract_tools_call_params(params: Option<&Value>) -> (&str, Value) {
    let tool_name = params
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let arguments = params
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or(json!({}));
    (tool_name, arguments)
}

/// Parse JSON-RPC request or notification
/// Returns (Option<RequestId>, method, params) - id is None for notifications
#[allow(clippy::result_large_err)] // JsonRpcResponse used directly as HTTP error body
pub(super) fn parse_request(
    value: &Value,
) -> Result<(Option<RequestId>, String, Option<Value>), JsonRpcResponse> {
    // Check jsonrpc version
    let jsonrpc = value.get("jsonrpc").and_then(|v| v.as_str());
    if jsonrpc != Some("2.0") {
        return Err(JsonRpcResponse::error(
            None,
            -32600,
            "Invalid JSON-RPC version",
        ));
    }

    // Get ID (required for requests, missing for notifications)
    let id = value.get("id").and_then(extract_request_id);

    // Get method
    let method = value
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcResponse::error(id.clone(), -32600, "Missing method"))?;

    // Get params (optional)
    let params = value.get("params").cloned();

    // For notifications (methods starting with "notifications/"), id is optional
    // For requests, id is required
    if !is_notification_method(method) && id.is_none() {
        return Err(JsonRpcResponse::error(None, -32600, "Missing id"));
    }

    Ok((id, method.to_string(), params))
}
