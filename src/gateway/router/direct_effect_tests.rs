// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route's reach and its declared effect. A direct call names a
//! registry backend; a capability provider is no registry backend, so the
//! direct route answers its name as absent and never records a grant.

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::{ApiKeyConfig, AuthConfig, api_key_digest_spec};
use crate::gateway::meta_mcp::grant_audit_fixture::{
    CAPS, Endpoint, PERSONAL, capability_backend, entries, grant, grants, logger,
};
use crate::security::audit::AuditFailurePolicy;

const KEY: &str = "alice-direct-key";
const ALICE: (&str, &str) = ("api_key", "alice");

fn alice_auth() -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(api_key_digest_spec(KEY.as_bytes())),
            expires_at: None,
            name: "alice".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            // Held by one person; its grant subject is (`api_key`, name).
            kind: crate::config::ApiKeyKind::Personal,
            ..Default::default()
        }],
        ..AuthConfig::default()
    }
}

/// POST `body` to `uri` as alice: the status and the JSON answer.
async fn post(router: &axum::Router, uri: &str, body: Value) -> (axum::http::StatusCode, Value) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {KEY}"))
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    let response = router.clone().oneshot(request).await.expect("an answer");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn tools_call(name: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": arguments}})
}

/// GUARD (probe): alice holds a matched grant on the personal capability,
/// proven by the meta route passing it. The same capability named on the
/// direct route is answered absent: nothing reaches the capability, and the
/// direct route's record names no grant and records no declared effect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_direct_reaches_the_capability_backend() {
    let endpoint = Endpoint::start(false).await;
    let dir = tempfile::tempdir().expect("a log directory");
    let log = logger(&dir, AuditFailurePolicy::FailClosed);
    let mut meta =
        crate::gateway::meta_mcp::MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()))
            .with_identity_grants(grants(vec![grant("g-direct", ALICE, ALICE)]));
    meta.enable_transparency_log(Arc::clone(&log));
    meta.set_capabilities(capability_backend(endpoint.port, ALICE));
    let auth = alice_auth();
    let (mut state, _store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(log);
    let router = super::create_router(state);

    let (_, through_meta) = post(
        &router,
        "/mcp",
        tools_call(
            "gateway_invoke",
            json!({"server": CAPS, "tool": PERSONAL, "arguments": {}}),
        ),
    )
    .await;
    // An API-key caller passes its grant and is then refused at execution:
    // a key carries no propagated identity (capability/execution_context.rs).
    // So the grant matching is shown by the refusal past it, as the router's
    // grant-key rows pin it.
    let meta_text = through_meta.to_string();
    assert!(
        !meta_text.contains("Identity grant denied")
            && meta_text.contains("caller identity is required"),
        "premise: alice's grant matches on the meta route: {through_meta}"
    );
    let before = entries(&dir).len();

    let (status, direct) = post(
        &router,
        &format!("/mcp/{CAPS}"),
        tools_call(PERSONAL, json!({})),
    )
    .await;
    eprintln!("PROBE direct {CAPS}/{PERSONAL}: {status} {direct}");
    assert_eq!(
        endpoint.arrivals(),
        1,
        "the direct call reached the capability: {direct}"
    );
    assert!(
        direct.get("result").is_none(),
        "answered as present: {direct}"
    );
    let after = entries(&dir).split_off(before);
    let text = serde_json::to_string(&after).expect("entries serialise");
    assert!(
        !text.contains("g-direct"),
        "a direct record names the grant: {text}"
    );
    assert!(
        !text.contains("grant_id"),
        "a direct record names a grant: {text}"
    );
    assert!(
        !text.contains("declared_effect") && !text.contains("capability_definition"),
        "the absent answer recorded an effect: {text}"
    );
}
