use axum::{body::to_bytes, http::StatusCode};
use serde_json::Value;

use super::{bearer_unauthorized_response, forbidden_response, rate_limited_response};

async fn response_json(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn bearer_unauthorized_sets_status_header_and_jsonrpc_shape() {
    let response = bearer_unauthorized_response("Missing Authorization header");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["WWW-Authenticate"], "Bearer");
    assert!(response.headers().get("Retry-After").is_none());

    let json = response_json(response).await;
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32000);
    assert_eq!(json["error"]["message"], "Missing Authorization header");
    assert_eq!(json["id"], Value::Null);
}

#[tokio::test]
async fn forbidden_sets_status_without_extra_headers() {
    let response = forbidden_response("Scope denied");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response.headers().get("WWW-Authenticate").is_none());
    assert!(response.headers().get("Retry-After").is_none());

    let json = response_json(response).await;
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32003);
    assert_eq!(json["error"]["message"], "Scope denied");
    assert_eq!(json["id"], Value::Null);
}

#[tokio::test]
async fn rate_limited_sets_status_header_and_preserves_message_escaping() {
    let message = "Rate limit exceeded for client 'cli-\"a\"\\\\b\\n'. Try again later.";
    let response = rate_limited_response(message);

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["Retry-After"], "60");
    assert!(response.headers().get("WWW-Authenticate").is_none());

    let json = response_json(response).await;
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32000);
    assert_eq!(json["error"]["message"], message);
    assert_eq!(json["id"], Value::Null);
}
