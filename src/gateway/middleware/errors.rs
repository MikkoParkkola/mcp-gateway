use axum::{
    Json,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;

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
    let mut response = (
        status,
        Json(json!({
            "jsonrpc": "2.0",
            "error": {
                "code": code,
                "message": message.into()
            },
            "id": null
        })),
    )
        .into_response();

    if let Some((name, value)) = header {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }

    response
}
