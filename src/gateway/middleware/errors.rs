use axum::{http::StatusCode, response::Response};

use crate::gateway::http_error::{attach_static_header, json_response, jsonrpc_error_body};

pub(crate) fn bearer_unauthorized_response(message: &str) -> Response {
    jsonrpc_error_response(
        StatusCode::UNAUTHORIZED,
        -32000,
        message,
        Some(("WWW-Authenticate", "Bearer")),
    )
}

pub(crate) fn forbidden_response(message: &str) -> Response {
    jsonrpc_error_response(StatusCode::FORBIDDEN, -32003, message, None)
}

pub(crate) fn rate_limited_response(message: impl Into<String>) -> Response {
    jsonrpc_error_response(
        StatusCode::TOO_MANY_REQUESTS,
        -32000,
        message,
        Some(("Retry-After", "60")),
    )
}

fn jsonrpc_error_response(
    status: StatusCode,
    code: i32,
    message: impl Into<String>,
    header: Option<(&'static str, &'static str)>,
) -> Response {
    let mut response = json_response(status, jsonrpc_error_body(code, message));

    if let Some((name, value)) = header {
        attach_static_header(&mut response, name, value);
    }

    response
}
