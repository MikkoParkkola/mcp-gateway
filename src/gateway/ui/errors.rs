use axum::Json;
use axum::http::StatusCode;
use serde_json::Value;

use crate::gateway::http_error::{flat_error_body, json_body, structured_error_body};

pub(super) fn flat_error(
    status: StatusCode,
    message: impl Into<String>,
) -> (StatusCode, Json<Value>) {
    json_body(status, flat_error_body(message))
}

pub(super) fn structured_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> (StatusCode, Json<Value>) {
    json_body(status, structured_error_body(code, message))
}

pub(super) fn admin_auth_required() -> (StatusCode, Json<Value>) {
    flat_error(StatusCode::FORBIDDEN, "Admin authentication required")
}

pub(super) fn auth_required(status: StatusCode) -> (StatusCode, Json<Value>) {
    flat_error(status, "Authentication required")
}

pub(super) fn config_path_unavailable() -> (StatusCode, Json<Value>) {
    flat_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "Config file path not available; cannot persist changes",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn admin_auth_required_shape_is_stable() {
        let (status, body) = admin_auth_required();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body.0, json!({ "error": "Admin authentication required" }));
    }

    #[test]
    fn auth_required_preserves_caller_status() {
        let (status, body) = auth_required(StatusCode::UNAUTHORIZED);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body.0, json!({ "error": "Authentication required" }));
    }

    #[test]
    fn config_path_unavailable_shape_is_stable() {
        let (status, body) = config_path_unavailable();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body.0,
            json!({ "error": "Config file path not available; cannot persist changes" })
        );
    }

    #[test]
    fn flat_error_uses_error_field() {
        let (status, body) = flat_error(StatusCode::CONFLICT, "example");
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body.0, json!({ "error": "example" }));
    }

    #[test]
    fn structured_error_uses_error_and_message_fields() {
        let (status, body) = structured_error(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "bad capability name",
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body.0,
            json!({
                "error": "invalid_name",
                "message": "bad capability name",
            })
        );
    }
}
