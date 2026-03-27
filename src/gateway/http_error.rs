#[cfg(test)]
use axum::body::to_bytes;
use axum::{
    Json,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

pub(crate) fn json_body(status: StatusCode, body: Value) -> (StatusCode, Json<Value>) {
    (status, Json(body))
}

pub(crate) fn json_response(status: StatusCode, body: Value) -> Response {
    json_body(status, body).into_response()
}

#[cfg(feature = "webui")]
pub(crate) fn flat_error_body(message: impl Into<String>) -> Value {
    json!({ "error": message.into() })
}

#[cfg(feature = "webui")]
pub(crate) fn structured_error_body(code: &str, message: impl Into<String>) -> Value {
    json!({
        "error": code,
        "message": message.into(),
    })
}

pub(crate) fn request_scoped_error_body(message: impl Into<String>, request_id: &str) -> Value {
    json!({
        "error": message.into(),
        "request_id": request_id,
    })
}

pub(crate) fn jsonrpc_error_body(code: i32, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "error": {
            "code": code,
            "message": message.into(),
        },
        "id": null,
    })
}

pub(crate) fn attach_static_header(
    response: &mut Response,
    name: &'static str,
    value: &'static str,
) {
    response
        .headers_mut()
        .insert(name, HeaderValue::from_static(value));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn json_response_preserves_status_and_body() {
        let response = json_response(StatusCode::CONFLICT, json!({ "error": "example" }));

        assert_eq!(response.status(), StatusCode::CONFLICT);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, json!({ "error": "example" }));
    }

    #[test]
    fn jsonrpc_error_body_shape_is_stable() {
        assert_eq!(
            jsonrpc_error_body(-32003, "Forbidden"),
            json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32003,
                    "message": "Forbidden",
                },
                "id": null,
            })
        );
    }

    #[test]
    fn request_scoped_error_body_shape_is_stable() {
        assert_eq!(
            request_scoped_error_body("Invalid signature", "req-123"),
            json!({
                "error": "Invalid signature",
                "request_id": "req-123",
            })
        );
    }

    #[test]
    fn attach_static_header_sets_header() {
        let mut response = json_response(StatusCode::OK, json!({}));

        attach_static_header(&mut response, "Retry-After", "60");

        assert_eq!(response.headers()["Retry-After"], "60");
    }

    #[cfg(feature = "webui")]
    #[test]
    fn flat_and_structured_error_bodies_are_stable() {
        assert_eq!(flat_error_body("example"), json!({ "error": "example" }));
        assert_eq!(
            structured_error_body("invalid_name", "bad capability name"),
            json!({
                "error": "invalid_name",
                "message": "bad capability name",
            })
        );
    }
}
