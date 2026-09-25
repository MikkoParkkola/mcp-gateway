// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7570.ATTEST.1 part 3: under `enforce`, every method the direct route
//! forwards is attested, not only `tools/call`.
//!
//! | Method | Capability |
//! |---|---|
//! | `tools/call`, `prompts/get` | `params.name` |
//! | `resources/read`, `resources/subscribe`, `resources/unsubscribe` | `params.uri` |
//! | `*/list`, `completion/complete`, `logging/setLevel` | none: an authentic token |
//! | any other forwarded method | `"*"` |
//! | `initialize`, `ping`, `notifications/*` | exempt |

use super::*;
use pretty_assertions::assert_eq;

const URI_A: &str = "file:///a";
const URI_B: &str = "file:///b";

async fn enforced() -> (axum::Router, Arc<RecordingTransport>, tempfile::TempDir) {
    router_with(Some(AttestationMode::Enforce), false).await
}

fn assert_admitted(what: &str, json: &Value) {
    assert!(
        json["error"]["code"] != json!(-32002),
        "{what} must pass attestation: {json}"
    );
}

fn assert_attestation_refused(what: &str, json: &Value) {
    assert_eq!(json["error"]["code"], -32002, "{what}: {json}");
    let message = json["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("direct_route"), "{what}: {json}");
}

/// Every forwarding method, with a params object that names its target.
fn forwarding_methods() -> Vec<(&'static str, Value)> {
    vec![
        ("tools/call", json!({"name": TOOL, "arguments": {}})),
        ("tools/list", json!({})),
        ("resources/list", json!({})),
        ("resources/read", json!({"uri": URI_A})),
        ("resources/subscribe", json!({"uri": URI_A})),
        ("resources/unsubscribe", json!({"uri": URI_A})),
        ("prompts/list", json!({})),
        ("prompts/get", json!({"name": "p"})),
        (
            "completion/complete",
            json!({"ref": {"type": "ref/prompt", "name": "p"}}),
        ),
        ("vendor/do", json!({})),
    ]
}

#[tokio::test]
async fn direct_route_enforce_refuses_every_forwarding_method() {
    let (router, transport, _store) = enforced().await;
    for (method, params) in forwarding_methods() {
        let (_, json) = rpc(&router, "/mcp/demo", method, params, None).await;
        assert_attestation_refused(method, &json);
    }
    let forwarded = transport.all.lock().unwrap().clone();
    assert!(
        forwarded.is_empty(),
        "nothing may reach the backend: {forwarded:?}"
    );
}

/// A URI or prompt capability admits exactly that target.
#[tokio::test]
async fn direct_route_enforce_scopes_resources_and_prompts() {
    let (router, _transport, _store) = enforced().await;
    let token = token_with(&[URI_A, "p"]);
    for method in [
        "resources/read",
        "resources/subscribe",
        "resources/unsubscribe",
    ] {
        let (_, json) = rpc(
            &router,
            "/mcp/demo",
            method,
            json!({"uri": URI_A}),
            Some(&token),
        )
        .await;
        assert_admitted(method, &json);
        let (_, json) = rpc(
            &router,
            "/mcp/demo",
            method,
            json!({"uri": URI_B}),
            Some(&token),
        )
        .await;
        assert_attestation_refused(method, &json);
    }
    let (_, json) = rpc(
        &router,
        "/mcp/demo",
        "prompts/get",
        json!({"name": "p"}),
        Some(&token),
    )
    .await;
    assert_admitted("prompts/get p", &json);
    let (_, json) = rpc(
        &router,
        "/mcp/demo",
        "prompts/get",
        json!({"name": "q"}),
        Some(&token),
    )
    .await;
    assert_attestation_refused("prompts/get q", &json);
}

/// A missing target is checked against the empty capability, which only a
/// `"*"` token satisfies. Mapping it to "authentic only" would widen scope.
#[tokio::test]
async fn direct_route_enforce_missing_field_needs_a_star_token() {
    let (router, _transport, _store) = enforced().await;
    let calls = [
        ("resources/read", json!({})),
        ("prompts/get", json!({})),
        ("tools/call", json!({"arguments": {}})),
    ];
    let scoped = token_with(&["x"]);
    for (method, params) in &calls {
        let (_, json) = rpc(&router, "/mcp/demo", method, params.clone(), Some(&scoped)).await;
        assert_attestation_refused(method, &json);
    }
    let star = token_with(&["*"]);
    for (method, params) in calls {
        let (_, json) = rpc(&router, "/mcp/demo", method, params, Some(&star)).await;
        assert_admitted(method, &json);
    }
}

/// Owner ruling: a method outside the table needs `"*"`, so a tool-scoped
/// token cannot drive a vendor method with unknown side effects.
#[tokio::test]
async fn direct_route_enforce_unknown_method_needs_star() {
    let (router, transport, _store) = enforced().await;
    let (_, json) = rpc(
        &router,
        "/mcp/demo",
        "vendor/do",
        json!({}),
        Some(&token_for(TOOL)),
    )
    .await;
    assert_attestation_refused("vendor/do with a tool token", &json);
    assert!(transport.all.lock().unwrap().is_empty(), "no dispatch");
    let (_, json) = rpc(
        &router,
        "/mcp/demo",
        "vendor/do",
        json!({}),
        Some(&token_with(&["*"])),
    )
    .await;
    assert_admitted("vendor/do with *", &json);
}

/// Discovery needs an authentic token, not a matching capability; a forged
/// token is still refused.
#[tokio::test]
async fn direct_route_enforce_list_needs_only_an_authentic_token() {
    let (router, _transport, _store) = enforced().await;
    let token = token_for(TOOL);
    for method in [
        "tools/list",
        "resources/list",
        "prompts/list",
        "completion/complete",
    ] {
        let (_, json) = rpc(&router, "/mcp/demo", method, json!({}), Some(&token)).await;
        assert_admitted(method, &json);
        let (_, json) = rpc(
            &router,
            "/mcp/demo",
            method,
            json!({}),
            Some("forged.token"),
        )
        .await;
        assert_attestation_refused(method, &json);
    }
}

/// Positive control: the exempt methods pass under enforce with no token.
#[tokio::test]
async fn direct_route_exempt_methods_pass_without_token() {
    let (router, _transport, _store) = enforced().await;
    for method in ["initialize", "ping"] {
        let (_, json) = rpc(&router, "/mcp/demo", method, json!({}), None).await;
        assert_admitted(method, &json);
    }
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string(),
        ))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

/// The token never reaches a backend, whatever the method and whichever arm
/// (sanitized or passthrough) forwards it. The raw token string is searched
/// for, not only the `_meta` key.
#[tokio::test]
async fn direct_route_token_never_forwarded_any_method() {
    for passthrough in [false, true] {
        let (router, transport, _store) =
            router_with(Some(AttestationMode::Enforce), passthrough).await;
        let token = token_with(&[URI_A, "p", TOOL]);
        for (method, params) in [
            ("resources/read", json!({"uri": URI_A})),
            ("prompts/get", json!({"name": "p"})),
            ("tools/call", json!({"name": TOOL, "arguments": {}})),
        ] {
            let (_, json) = rpc(&router, "/mcp/demo", method, params, Some(&token)).await;
            assert_admitted(method, &json);
        }
        let forwarded = transport.all.lock().unwrap().len();
        assert_eq!(forwarded, 3, "passthrough={passthrough}");
        assert_raw_token_never_forwarded(&transport, &token);
    }
}

/// A forged token and a token for another tool are refused on both routes.
#[tokio::test]
async fn direct_route_forged_and_wrong_tool_tokens_refused() {
    let (router, transport, _store) = enforced().await;
    for token in ["forged.token".to_string(), token_for("other_tool")] {
        let (_, json) = call(&router, "/mcp/demo", Some(&token)).await;
        assert_refused(&json, "direct_route");
        let (_, json) = call(&router, "/mcp", Some(&token)).await;
        assert_refused(&json, "gateway_invoke");
    }
    assert!(transport.seen.lock().unwrap().is_empty(), "no dispatch");
}

/// A replay under the same idempotency key still needs a token.
#[tokio::test]
async fn direct_route_replay_needs_a_token() {
    let (router, transport, _store) = enforced().await;
    let key_meta = crate::protocol::mrtr::IDEMPOTENCY_KEY_META;
    let token = token_for(TOOL);
    let first = json!({"name": TOOL, "arguments": {},
        "_meta": { key_meta: "replay-1", (ATTESTATION_META): token }});
    let (_, json) = rpc(&router, "/mcp/demo", "tools/call", first, None).await;
    assert_admitted("first call", &json);
    let replay = json!({"name": TOOL, "arguments": {}, "_meta": { key_meta: "replay-1" }});
    let (_, json) = rpc(&router, "/mcp/demo", "tools/call", replay, None).await;
    assert_attestation_refused("replay without a token", &json);
    assert_eq!(transport.seen.lock().unwrap().len(), 1, "one dispatch");
}

/// The direct-route check runs before identity-propagation minting: an
/// unattested call is refused with -32002 and never reaches the mint, whose
/// missing route audit would otherwise answer 500. The attested call reaching
/// that 500 is the control that the mint still runs after the check.
#[tokio::test]
async fn direct_route_refusal_precedes_identity_minting() {
    use crate::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
    };
    let config = BackendConfig {
        transport: crate::config::TransportConfig::Http {
            http_url: "https://mem.internal/mcp".to_string(),
            streamable_http: true,
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
    let (state, _store) =
        super::super::test_router_app_state_minting_without_route_audit(backend).await;
    let mut app = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("fixture state is exclusive"));
    let meta =
        Arc::try_unwrap(app.meta_mcp).unwrap_or_else(|_| panic!("fixture meta is exclusive"));
    let key = std::str::from_utf8(KEY).expect("utf-8 key");
    let (validator, mode) = crate::attestation::wiring::enforce_from_env_file(key, "route");
    app.meta_mcp = Arc::new(meta.with_attestation(validator, mode));
    let router = create_router(Arc::new(app));

    for (token, expect_attestation_refusal) in [(None, true), (Some(token_for("read")), false)] {
        let mut params = json!({"name": "read", "arguments": {}});
        if let Some(token) = &token {
            params["_meta"] = json!({ (ATTESTATION_META): token });
        }
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp/demo")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
                    .to_string(),
            ))
            .unwrap();
        request
            .extensions_mut()
            .insert(crate::key_server::oidc::VerifiedIdentity {
                subject: "alice".to_string(),
                email: "alice@corp".to_string(),
                name: None,
                groups: vec![],
                issuer: "https://idp".to_string(),
            });
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        if expect_attestation_refusal {
            assert_attestation_refused("unattested call", &json);
        } else {
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{json}");
            assert_eq!(
                json["error"]["message"],
                "identity-propagation audit unavailable"
            );
        }
    }
}
