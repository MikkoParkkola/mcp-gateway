// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A11 on the direct route `POST /mcp/{name}` (T7-direct, T7-direct-b).
//!
//! The managed MCP fixture's `MetaMcp` and backend registry are installed into
//! the router harness, so the request goes through the real direct handler,
//! the real credential mint and the real post-dispatch Err arm. No offers are
//! installed, so a reconnect refusal takes `direct_refusal`'s plain -32003 form
//! (`gateway/router/accounts/offer.rs:143-163`).

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::super::super::account_resolver_fixture::{
    ALICE_WORK_TOKEN, Bind, Custody, Descriptors, Dispatches, ProviderStep, ROTATED_TOKEN, WORK,
    account_key, custody_with_steps, gateway, grant, identity, slots,
};
use crate::gateway::router::create_router;
use crate::gateway::router::tests::direct_route_state_with_identity;

const FRESH: u64 = u64::MAX;

struct Direct {
    router: axum::Router,
    custody: Custody,
    dispatches: Arc<Dispatches>,
    _store: tempfile::TempDir,
    _audit: tempfile::NamedTempFile,
}

/// The direct route refuses to mint for a required backend (a managed one
/// always is) without an audit sink, so the router state needs one.
fn route_audit(file: &tempfile::NamedTempFile) -> Arc<crate::security::TransparencyLogger> {
    let config = crate::security::TransparencyLogConfig {
        enabled: true,
        path: file.path().to_string_lossy().to_string(),
        key_id: "a11-direct".to_string(),
        shared_secret: String::new(),
    };
    Arc::new(crate::security::TransparencyLogger::open(Arc::new(config)).expect("logger opens"))
}

async fn direct(steps: &[ProviderStep]) -> Direct {
    let custody = custody_with_steps(
        &[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))],
        ROTATED_TOKEN,
        steps,
    );
    let installed = custody.installed();
    let (meta, dispatches) = gateway(
        &[("mail", Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &installed,
        &slots(&[("alice", WORK)]),
    );
    let (mut state, store) =
        direct_route_state_with_identity(crate::config::AgentIdentityConfig::default()).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = Arc::clone(&meta.backends);
    state_mut.meta_mcp = Arc::new(meta);
    let audit = tempfile::NamedTempFile::new().expect("audit file");
    state_mut.transparency_log = Some(route_audit(&audit));
    Direct {
        router: create_router(state),
        custody,
        dispatches,
        _store: store,
        _audit: audit,
    }
}

async fn call_as_alice(router: &axum::Router) -> (StatusCode, Value) {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read", "arguments": {"folder": "inbox"}},
    });
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/mail")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("request builds");
    // Auth is off in this harness, so the middleware leaves the identity in place.
    request.extensions_mut().insert(identity("alice"));
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).expect("a JSON-RPC body"),
    )
}

/// T7-direct: a 401 on a revoked grant forces one refresh and answers with the
/// direct route's account refusal, not today's HTTP 500.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_route_401_uses_propagated_lease() {
    let fixture = direct(&[ProviderStep::InvalidGrant]).await;
    fixture.dispatches.answer_with(&[401]);

    let (status, body) = call_as_alice(&fixture.router).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], -32003, "{body}");
    assert_eq!(fixture.custody.refreshes(), 1, "exactly one forced refresh");
    assert_eq!(fixture.dispatches.count(), 1, "the 401 is not retried");
}

/// T7-direct-b: a rotation answers with the rejection carrier, so the caller
/// knows a retry presents a new token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_route_401_with_live_grant_says_retry() {
    let fixture = direct(&[ProviderStep::Rotate(ROTATED_TOKEN)]).await;
    fixture.dispatches.answer_with(&[401]);

    let (_status, body) = call_as_alice(&fixture.router).await;

    assert_eq!(
        body["error"]["data"]["error_code"], "UPSTREAM_AUTH_REJECTED",
        "{body}"
    );
    assert_eq!(body["error"]["data"]["retry"], true, "{body}");
    assert_eq!(fixture.custody.refreshes(), 1);
    assert_eq!(
        fixture.dispatches.count(),
        1,
        "the call itself is not retried"
    );
}
