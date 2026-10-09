// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Response builders and the backend handler.

use super::*;
use pretty_assertions::assert_eq;

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
/// MIK-7759: Streamable HTTP (2025-06-18, 2025-11-25) — an accepted
/// notification or client response MUST get 202 with no body.
async fn build_accepted_response_sets_status_session_header_and_empty_body() {
    let response = build_accepted_response("sess-accepted");

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.headers()["mcp-session-id"], "sess-accepted");
    assert!(
        response.headers().get("content-type").is_none(),
        "a bodiless 202 carries no content type"
    );

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert!(body.is_empty(), "202 body must be empty, got {body:?}");
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
async fn build_http_error_response_without_request_id_includes_null_id_field() {
    let (status, body) =
        build_http_error_response(None, -32700, "Parse error", StatusCode::BAD_REQUEST);
    let response = (status, body).into_response();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let object = json.as_object().unwrap();
    assert!(object.contains_key("id"));
    assert_eq!(json["id"], Value::Null);
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32700);
    assert_eq!(json["error"]["message"], "Parse error");
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

/// MIK-8195: a sampling request with no params is refused before it is
/// forwarded, as an elicitation request is.
#[tokio::test]
async fn parse_sampling_params_missing_returns_bad_request_with_session_header() {
    let response = parse_sampling_params(RequestId::Number(9), None, "sess-sample").unwrap_err();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["mcp-session-id"], "sess-sample");

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], -32602);
    assert_eq!(json["error"]["message"], "Missing sampling params");
    assert_eq!(json["id"], json!(9));
}

/// MIK-8195: params valid in every field but the required `messages` are
/// refused, and the refusal names `messages`, so the row cannot pass on
/// another field's refusal.
#[tokio::test]
async fn parse_sampling_params_invalid_returns_bad_request_with_context() {
    let response = parse_sampling_params(
        RequestId::String("req-1".to_string()),
        Some(json!({"maxTokens": 16})),
        "sess-sample",
    )
    .unwrap_err();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["mcp-session-id"], "sess-sample");

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], -32602);
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("Invalid sampling params:")
    );
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("messages"),
        "the refusal names the missing field: {json}"
    );
    assert_eq!(json["id"], json!("req-1"));
}

#[tokio::test]
async fn backend_handler_invalid_json_returns_jsonrpc_parse_error() {
    let (state, _store) = test_router_app_state().await;
    let router = create_router(state);
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
    let (state, _store) = test_router_app_state().await;
    let router = create_router(state);
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
async fn backend_handler_preserves_callers_jsonrpc_id_on_success() {
    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport: Arc<dyn Transport> = Arc::new(RouterNotificationTestTransport::success());
    backend.set_transport_for_test(transport);

    let (state, _store) = test_router_app_state_with_backend(backend).await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": "caller-initialize-41",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "test-client", "version": "1.0" }
                }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], "caller-initialize-41");
    assert_eq!(json["result"], json!({"ok": true}));
}

#[tokio::test]
async fn backend_handler_discovery_method_fails_closed_for_required_propagation() {
    // ADR-007 IDP.2/IDP.3 regression guard: a discovery method (resources/list)
    // on a propagation-`required` backend must fail closed (403) when the
    // request carries no verified identity — never downgrade to the shared
    // static credential. Guards the fix that extends the per-user credential
    // gate beyond `tools/call` to every backend-reaching method (MIK-6728).
    use crate::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
    };

    let config = BackendConfig {
        identity_propagation: Some(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "https://mem.internal/mcp".to_string(),
            required: true,
            session_mode: SessionMode::Stateless,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        "demo",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));

    let (state, _store) = test_router_app_state_with_backend(backend).await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "resources/list"
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], -32003);
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("required"),
        "fail-closed error message: {}",
        json["error"]["message"]
    );
}

#[tokio::test]
async fn backend_handler_required_mint_without_route_audit_fails_closed_generically() {
    // MIK-6740 operator-misconfig fail-OPEN guard on the DIRECT route: a
    // `required` backend whose per-user credential mints successfully but whose
    // route-side transparency log is UNCONFIGURED must fail closed (500) — never
    // ship the credential without a durable audit record. CWE-209: the 500 body
    // must be a GENERIC client message, never the transparency-log path / IO
    // error.
    use crate::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
    };
    use crate::key_server::oidc::VerifiedIdentity;

    let config = BackendConfig {
        transport: crate::config::TransportConfig::Http {
            http_url: "https://mem.internal/mcp".to_string(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        identity_propagation: Some(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "https://mem.internal/mcp".to_string(),
            required: true,
            session_mode: SessionMode::Stateless,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        enabled: true,
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        "demo",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let (state, _store) = test_router_app_state_minting_without_route_audit(backend).await;
    let router = create_router(state);

    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "read", "arguments": {} }
            })
            .to_string(),
        ))
        .unwrap();
    // Inject a verified end-user identity so the required backend actually MINTS
    // a per-user credential. Auth is disabled in this test state, so the
    // middleware does not overwrite the extension.
    request.extensions_mut().insert(VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@corp".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://idp".to_string(),
    });

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let msg = json["error"]["message"].as_str().unwrap();
    // Generic client-facing message — the whole point of the CWE-209 fix.
    assert_eq!(msg, "identity-propagation audit unavailable");
    // Defense-in-depth: no filesystem path or IO detail leaks to the client.
    assert!(!msg.contains('/'), "must not leak a filesystem path: {msg}");
    assert!(
        !msg.to_lowercase().contains("write failed"),
        "must not leak audit IO detail: {msg}"
    );
}

#[tokio::test]
async fn backend_handler_notification_uses_notify_and_returns_accepted() {
    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport = Arc::new(RouterNotificationTestTransport::success());
    let transport_dyn: Arc<dyn Transport> = transport.clone();
    backend.set_transport_for_test(transport_dyn);

    let (state, _store) = test_router_app_state_with_backend(backend).await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": { "progress": 50 }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(response.headers().get("content-type").is_none());
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert!(
        body.is_empty(),
        "MIK-7759: 202 body must be empty, got {body:?}"
    );
    assert!(transport.request_methods.lock().unwrap().is_empty());
    assert_eq!(
        transport.notify_methods.lock().unwrap().as_slice(),
        ["notifications/initialized"]
    );
}

#[tokio::test]
async fn backend_handler_notification_failure_surfaces_error() {
    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport = Arc::new(RouterNotificationTestTransport::fail("notify failed"));
    let transport_dyn: Arc<dyn Transport> = transport.clone();
    backend.set_transport_for_test(transport_dyn);

    let (state, _store) = test_router_app_state_with_backend(backend).await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": { "progress": 50 }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32000);
    assert_eq!(json["error"]["message"], "Transport error: notify failed");
    assert_eq!(json["id"], Value::Null);
    assert!(transport.request_methods.lock().unwrap().is_empty());
    assert_eq!(
        transport.notify_methods.lock().unwrap().as_slice(),
        ["notifications/initialized"]
    );
}

#[tokio::test]
async fn backend_handler_tools_call_enforces_api_key_tool_scope() {
    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport = Arc::new(RouterNotificationTestTransport::success());
    let transport_dyn: Arc<dyn Transport> = transport.clone();
    backend.set_transport_for_test(transport_dyn);

    let (state, _store) = test_router_app_state_with_auth(&scoped_auth_config(false)).await;
    let _ = state.backends.register(backend);
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("authorization", "Bearer scoped-key")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "blocked_tool",
                    "arguments": {}
                }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], -32600);
    assert!(
        json["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("allowlist"))
    );
    assert!(transport.request_methods.lock().unwrap().is_empty());
}

#[tokio::test]
async fn backend_handler_direct_route_stamps_bypass_provenance() {
    // Rung 3: the direct /mcp/{name} passthrough must also carry a signed
    // provenance receipt, tagged cache=Bypass (it never consults the meta
    // cache). Without this a client routes around provenance by URL choice.
    use crate::trust::{CacheOutcome, SignedResultProvenance};

    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::r2_off(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport: Arc<dyn Transport> = Arc::new(RouterNotificationTestTransport::success());
    backend.set_transport_for_test(transport);

    let (state, _store) = test_router_app_state_with_meta(backend, |meta| {
        meta.enable_provenance_stamping(
            crate::attestation::BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
                .with_audience("test-gateway")
                .derive_domain(crate::attestation::RESULT_PROVENANCE_DOMAIN_INFO),
        );
    })
    .await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": { "name": "search", "arguments": {} }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let provenance = json
        .pointer("/result/_meta/provenance")
        .expect("direct route must stamp _meta.provenance on tools/call");
    let signed: SignedResultProvenance =
        serde_json::from_value(provenance.clone()).expect("provenance must deserialize");

    assert_eq!(
        signed.receipt.cache,
        CacheOutcome::Bypass,
        "direct route bypasses the meta cache → cache=Bypass"
    );
    assert_eq!(signed.receipt.backend_id, "demo");
    assert_eq!(signed.receipt.tool, "search");

    let validator = crate::attestation::AttestationValidator::new(
        crate::attestation::BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
            .with_audience("test-gateway"),
    );
    assert!(
        validator.verify_result_provenance(&signed),
        "direct-route receipt must verify under a twin validator"
    );
}

#[tokio::test]
async fn backend_handler_direct_route_no_provenance_when_disabled() {
    // Flag off (default MetaMcp, no signer): the direct route stays
    // byte-identical — no _meta.provenance appears.
    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport: Arc<dyn Transport> = Arc::new(RouterNotificationTestTransport::success());
    backend.set_transport_for_test(transport);

    let (state, _store) = test_router_app_state_with_backend(backend).await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": { "name": "search", "arguments": {} }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], 8);
    assert!(
        json.pointer("/result/_meta/provenance").is_none(),
        "flag off must not stamp provenance, got: {json}"
    );
}
