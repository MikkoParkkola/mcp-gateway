use super::helpers::{
    attach_session_header, build_accepted_response, build_error_response,
    build_http_error_response, build_json_response, extract_request_id, extract_tools_call_params,
    is_notification_method, parse_elicitation_params, parse_request,
};
use super::{AppState, create_router};
use crate::backend::BackendRegistry;
use crate::config::{AuthConfig, StreamingConfig};
use crate::gateway::test_helpers::MetaMcp;
use crate::gateway::{
    AgentAuthState, AgentRegistry, GatewayKeyPair, NotificationMultiplexer, ProxyManager,
    ResolvedAuthConfig,
};
use crate::mtls::{MtlsConfig, MtlsPolicy};
use crate::protocol::RequestId;
use axum::{
    body::to_bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use pretty_assertions::assert_eq;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

fn test_router_app_state() -> Arc<AppState> {
    let backends = Arc::new(BackendRegistry::new());
    let meta_mcp = Arc::new(MetaMcp::new(Arc::clone(&backends)));
    let streaming_config = StreamingConfig::default();
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        streaming_config.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(&AuthConfig::default()));
    let agent_auth = AgentAuthState::new(false, Arc::new(AgentRegistry::new()));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("gateway key generation"));

    Arc::new(AppState {
        backends,
        meta_mcp,
        meta_mcp_enabled: true,
        multiplexer,
        proxy_manager,
        streaming_config,
        auth_config,
        key_server: None,
        tool_policy: Arc::new(crate::security::ToolPolicy::default()),
        mtls_policy: Arc::new(MtlsPolicy::from_config(&MtlsConfig::default())),
        sanitize_input: false,
        ssrf_protection: false,
        inflight: Arc::new(tokio::sync::Semaphore::new(8)),
        agent_auth,
        gateway_key_pair,
        capability_dirs: Vec::new(),
        config_path: None,
        #[cfg(feature = "firewall")]
        firewall: None,
    })
}

// =====================================================================
// extract_request_id
// =====================================================================

#[test]
fn extract_request_id_string_value() {
    let val = json!("abc-123");
    let id = extract_request_id(&val).unwrap();
    assert_eq!(id, RequestId::String("abc-123".to_string()));
}

#[test]
fn extract_request_id_positive_integer() {
    let val = json!(42);
    let id = extract_request_id(&val).unwrap();
    assert_eq!(id, RequestId::Number(42));
}

#[test]
fn extract_request_id_negative_integer() {
    let val = json!(-1);
    let id = extract_request_id(&val).unwrap();
    assert_eq!(id, RequestId::Number(-1));
}

#[test]
fn extract_request_id_zero() {
    let val = json!(0);
    let id = extract_request_id(&val).unwrap();
    assert_eq!(id, RequestId::Number(0));
}

#[test]
fn extract_request_id_null_returns_none() {
    let val = json!(null);
    assert!(extract_request_id(&val).is_none());
}

#[test]
fn extract_request_id_bool_returns_none() {
    let val = json!(true);
    assert!(extract_request_id(&val).is_none());
}

#[test]
#[allow(clippy::approx_constant)] // 3.14 tests float input, not π
fn extract_request_id_float_returns_none() {
    let val = json!(3.14);
    assert!(extract_request_id(&val).is_none());
}

#[test]
fn extract_request_id_array_returns_none() {
    let val = json!([1, 2]);
    assert!(extract_request_id(&val).is_none());
}

#[test]
fn extract_request_id_object_returns_none() {
    let val = json!({"id": 1});
    assert!(extract_request_id(&val).is_none());
}

// =====================================================================
// is_notification_method
// =====================================================================

#[test]
fn notification_method_recognized() {
    assert!(is_notification_method("notifications/initialized"));
    assert!(is_notification_method("notifications/cancelled"));
    assert!(is_notification_method("notifications/"));
}

#[test]
fn regular_method_not_notification() {
    assert!(!is_notification_method("initialize"));
    assert!(!is_notification_method("tools/list"));
    assert!(!is_notification_method("tools/call"));
    assert!(!is_notification_method("ping"));
    assert!(!is_notification_method(""));
}

// =====================================================================
// extract_tools_call_params
// =====================================================================

#[test]
fn extract_tools_call_params_full() {
    let params = json!({"name": "my_tool", "arguments": {"key": "value"}});
    let (name, args) = extract_tools_call_params(Some(&params));
    assert_eq!(name, "my_tool");
    assert_eq!(args, json!({"key": "value"}));
}

#[test]
fn extract_tools_call_params_missing_name() {
    let params = json!({"arguments": {"key": "value"}});
    let (name, args) = extract_tools_call_params(Some(&params));
    assert_eq!(name, "");
    assert_eq!(args, json!({"key": "value"}));
}

#[test]
fn extract_tools_call_params_missing_arguments() {
    let params = json!({"name": "my_tool"});
    let (name, args) = extract_tools_call_params(Some(&params));
    assert_eq!(name, "my_tool");
    assert_eq!(args, json!({}));
}

#[test]
fn extract_tools_call_params_none_input() {
    let (name, args) = extract_tools_call_params(None);
    assert_eq!(name, "");
    assert_eq!(args, json!({}));
}

#[test]
fn extract_tools_call_params_empty_object() {
    let params = json!({});
    let (name, args) = extract_tools_call_params(Some(&params));
    assert_eq!(name, "");
    assert_eq!(args, json!({}));
}

// =====================================================================
// parse_request - valid requests
// =====================================================================

#[test]
fn parse_request_valid_with_string_id() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tools/list"
    });
    let (id, method, params) = parse_request(&req).unwrap();
    assert_eq!(id, Some(RequestId::String("req-1".to_string())));
    assert_eq!(method, "tools/list");
    assert!(params.is_none());
}

#[test]
fn parse_request_valid_with_numeric_id() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "ping"
    });
    let (id, method, params) = parse_request(&req).unwrap();
    assert_eq!(id, Some(RequestId::Number(42)));
    assert_eq!(method, "ping");
    assert!(params.is_none());
}

#[test]
fn parse_request_valid_with_params() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "my_tool", "arguments": {"q": "test"}}
    });
    let (id, method, params) = parse_request(&req).unwrap();
    assert_eq!(id, Some(RequestId::Number(1)));
    assert_eq!(method, "tools/call");
    assert!(params.is_some());
    let p = params.unwrap();
    assert_eq!(p["name"], "my_tool");
}

#[test]
fn parse_request_notification_without_id() {
    let req = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    let (id, method, _params) = parse_request(&req).unwrap();
    assert!(id.is_none());
    assert_eq!(method, "notifications/initialized");
}

#[test]
fn parse_request_notification_with_id_accepted() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "notifications/cancelled"
    });
    let (id, method, _params) = parse_request(&req).unwrap();
    assert_eq!(id, Some(RequestId::Number(99)));
    assert_eq!(method, "notifications/cancelled");
}

// =====================================================================
// parse_request - error cases
// =====================================================================

#[test]
fn parse_request_missing_jsonrpc_field() {
    let req = json!({"id": 1, "method": "ping"});
    let err = parse_request(&req).unwrap_err();
    assert!(err.error.is_some());
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
    assert!(
        err.error
            .as_ref()
            .unwrap()
            .message
            .contains("JSON-RPC version")
    );
}

#[test]
fn parse_request_wrong_jsonrpc_version() {
    let req = json!({"jsonrpc": "1.0", "id": 1, "method": "ping"});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
}

#[test]
fn parse_request_missing_method() {
    let req = json!({"jsonrpc": "2.0", "id": 1});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
    assert!(err.error.as_ref().unwrap().message.contains("method"));
}

#[test]
fn parse_request_non_notification_without_id() {
    let req = json!({"jsonrpc": "2.0", "method": "tools/list"});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
    assert!(err.error.as_ref().unwrap().message.contains("id"));
}

#[test]
fn parse_request_null_jsonrpc() {
    let req = json!({"jsonrpc": null, "id": 1, "method": "ping"});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
}

#[test]
fn parse_request_numeric_jsonrpc() {
    let req = json!({"jsonrpc": 2, "id": 1, "method": "ping"});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
}

#[test]
fn parse_request_method_is_not_string() {
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": 123});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
}

#[test]
fn parse_request_empty_object() {
    let req = json!({});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
}

#[test]
fn parse_request_initialize_method() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": "init-1",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        }
    });
    let (id, method, params) = parse_request(&req).unwrap();
    assert_eq!(id, Some(RequestId::String("init-1".to_string())));
    assert_eq!(method, "initialize");
    assert!(params.is_some());
}

// =====================================================================
// response helpers
// =====================================================================

#[tokio::test]
async fn build_error_response_sets_status_session_header_and_rpc_body() {
    let response = build_error_response(
        Some(RequestId::Number(7)),
        -32602,
        "Missing parameter",
        "sess-123",
        StatusCode::BAD_REQUEST,
    );

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["mcp-session-id"], "sess-123");

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32602);
    assert_eq!(json["error"]["message"], "Missing parameter");
    assert_eq!(json["id"], json!(7));
}

#[tokio::test]
async fn build_accepted_response_sets_status_session_header_and_empty_body() {
    let response = build_accepted_response("sess-accepted");

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.headers()["mcp-session-id"], "sess-accepted");

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json, json!({}));
}

#[tokio::test]
async fn build_json_response_skips_invalid_session_header_without_panicking() {
    let response = build_json_response(json!({"ok": true}), "sess\n123", StatusCode::OK);

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("mcp-session-id").is_none());

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json, json!({"ok": true}));
}

#[test]
fn attach_session_header_skips_invalid_session_header_without_panicking() {
    let mut headers = HeaderMap::new();

    attach_session_header(&mut headers, "sess\n123");

    assert!(headers.get("mcp-session-id").is_none());
}

#[tokio::test]
async fn build_http_error_response_sets_status_and_jsonrpc_body() {
    let (status, body) = build_http_error_response(
        Some(RequestId::String("req-403".to_string())),
        -32003,
        "Forbidden",
        StatusCode::FORBIDDEN,
    );
    let response = (status, body).into_response();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response.headers().get("mcp-session-id").is_none());

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32003);
    assert_eq!(json["error"]["message"], "Forbidden");
    assert_eq!(json["id"], json!("req-403"));
}

#[tokio::test]
async fn parse_elicitation_params_missing_returns_bad_request_with_session_header() {
    let response = parse_elicitation_params(RequestId::Number(9), None, "sess-elicit").unwrap_err();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["mcp-session-id"], "sess-elicit");

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], -32602);
    assert_eq!(json["error"]["message"], "Missing elicitation params");
    assert_eq!(json["id"], json!(9));
}

#[tokio::test]
async fn parse_elicitation_params_invalid_returns_bad_request_with_context() {
    let response = parse_elicitation_params(
        RequestId::String("req-1".to_string()),
        Some(json!({"message": 42})),
        "sess-elicit",
    )
    .unwrap_err();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["mcp-session-id"], "sess-elicit");

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], -32602);
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("Invalid elicitation params:")
    );
    assert_eq!(json["id"], json!("req-1"));
}

#[tokio::test]
async fn backend_handler_invalid_json_returns_jsonrpc_parse_error() {
    let router = create_router(test_router_app_state());
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from("{not json"))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32700);
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("Invalid JSON:")
    );
    assert_eq!(json["id"], Value::Null);
}

#[tokio::test]
async fn backend_handler_missing_backend_returns_jsonrpc_not_found() {
    let router = create_router(test_router_app_state());
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/missing-backend")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "ping"
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32001);
    assert_eq!(
        json["error"]["message"],
        "Backend not found: missing-backend"
    );
    assert_eq!(json["id"], Value::Null);
}

#[tokio::test]
async fn sse_handler_rejects_non_sse_accept_with_jsonrpc_error_shape() {
    let router = create_router(test_router_app_state());
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/mcp")
        .header("accept", "application/json")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32600);
    assert_eq!(
        json["error"]["message"],
        "Must accept text/event-stream for SSE notifications"
    );
    assert_eq!(json["id"], Value::Null);
}

// =====================================================================
// /metrics endpoint
// =====================================================================

#[cfg(feature = "metrics")]
#[tokio::test]
async fn metrics_endpoint_returns_200() {
    let router = create_router(test_router_app_state());
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    // Endpoint must always return 200 (body may be empty when recorder is not
    // installed in tests, but the route must be reachable).
    assert_eq!(response.status(), StatusCode::OK);
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn metrics_endpoint_includes_jsonrpc_request_counter() {
    crate::metrics::install();

    let router = create_router(test_router_app_state());
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": "metrics-jsonrpc-counter",
                "method": "metrics/test-counter",
                "params": {}
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let scrape = axum::http::Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(axum::body::Body::empty())
        .unwrap();
    let metrics_response = router.oneshot(scrape).await.unwrap();
    assert_eq!(metrics_response.status(), StatusCode::OK);

    let body = to_bytes(metrics_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("mcp_jsonrpc_requests_total"));
    assert!(text.contains("method=\"metrics/test-counter\""));
    assert!(text.contains("status=\"error\""));
}
