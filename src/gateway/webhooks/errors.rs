use axum::Json;
use axum::http::StatusCode;
use serde_json::{Value, json};

fn webhook_error(
    status: StatusCode,
    message: impl Into<String>,
    request_id: &str,
) -> (StatusCode, Json<Value>) {
    let message = message.into();
    (
        status,
        Json(json!({
            "error": message,
            "request_id": request_id,
        })),
    )
}

pub(super) fn invalid_json(
    message: impl Into<String>,
    request_id: &str,
) -> (StatusCode, Json<Value>) {
    webhook_error(StatusCode::BAD_REQUEST, message, request_id)
}

pub(super) fn invalid_signature(request_id: &str) -> (StatusCode, Json<Value>) {
    webhook_error(StatusCode::UNAUTHORIZED, "Invalid signature", request_id)
}

pub(super) fn transformation_failed(request_id: &str) -> (StatusCode, Json<Value>) {
    webhook_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Transformation failed",
        request_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_json_shape_is_stable() {
        let (status, body) = invalid_json("Invalid JSON: eof while parsing value", "req-123");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body.0,
            json!({
                "error": "Invalid JSON: eof while parsing value",
                "request_id": "req-123",
            })
        );
    }

    #[test]
    fn invalid_signature_shape_is_stable() {
        let (status, body) = invalid_signature("req-456");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            body.0,
            json!({
                "error": "Invalid signature",
                "request_id": "req-456",
            })
        );
    }

    #[test]
    fn transformation_failed_shape_is_stable() {
        let (status, body) = transformation_failed("req-789");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body.0,
            json!({
                "error": "Transformation failed",
                "request_id": "req-789",
            })
        );
    }
}
