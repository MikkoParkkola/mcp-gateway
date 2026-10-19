// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.1 T11 and U2: a stored read of a REST capability that
//! dispatches under a personal account (`auth.account`). A managed account
//! revoked after the task ran answers -32601 (T11); an external account has
//! no mint-free view, so it is unjudged and served on its catalogue (U2, the
//! stated residual). Driven through `/mcp` as alice.

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::AuthConfig;
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    CAPABILITY_SERVER, CAPABILITY_TOOL, CapabilityAccount,
};

fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
    })
}

async fn send(router: &axum::Router, method: &str, name: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": method, "params": params});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method)
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request.extensions_mut().insert(CapabilityAccount::alice());
    let response = router.clone().oneshot(request).await.expect("an answer");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn task_get(router: &axum::Router, id: &str) -> Value {
    send(
        router,
        "tasks/get",
        id,
        json!({"taskId": id, "_meta": modern_meta()}),
    )
    .await
}

/// A router over alice's capability account, and a finished task of it
/// whose stored result was delivered once.
async fn finished(account: &CapabilityAccount, key: &str) -> (axum::Router, String, impl Sized) {
    let (state, store) = super::tests::meta_fixture::test_router_app_state_with_meta(
        &AuthConfig::default(),
        None,
        |meta| account.install(meta),
    )
    .await;
    let router = super::create_router(Arc::clone(&state));
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let made = send(
        &router,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": CAPABILITY_SERVER, "tool": CAPABILITY_TOOL, "arguments": {}},
            "task": {}, "_meta": meta}),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let got = task_get(&router, &id).await;
        if got.pointer("/result/status") == Some(&json!("completed")) {
            assert!(got.get("error").is_none(), "control: delivered: {got}");
            return (router, id, (state, store));
        }
        assert!(
            std::time::Instant::now() < bound,
            "premise: completes: {got}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// T11: a capability's managed account revoked after the task ran: -32601.
/// Control (in `finished`): the grant live, the stored result is delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t11_a_capability_account_revoked_after_the_task_answers_absent() {
    let account = CapabilityAccount::start(false).await;
    let (router, id, _keep) = finished(&account, "s1-t11").await;
    account.revoke().await;
    let read = task_get(&router, &id).await;
    assert_eq!(
        read.pointer("/error/code"),
        Some(&json!(-32601)),
        "T11: {read}"
    );
}

/// U2 (M29): an external account has no mint-free view, so its outcome is
/// Unjudged and the read is judged on the catalogue alone: served (the
/// stated residual), never refused as `NoView`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u2_an_external_account_is_unjudged_and_served() {
    let account = CapabilityAccount::start(true).await;
    let (router, id, _keep) = finished(&account, "s1-u2").await;
    let read = task_get(&router, &id).await;
    assert!(read.get("error").is_none(), "U2: served: {read}");
    assert_eq!(
        read.pointer("/result/status"),
        Some(&json!("completed")),
        "U2: {read}"
    );
}

/// A router over `account`'s capability, armed with the idempotency cache
/// when `cache` is set (as production arms it).
async fn capability_router(account: &CapabilityAccount, cache: bool) -> (axum::Router, impl Sized) {
    let (state, store) = super::tests::meta_fixture::test_router_app_state_with_meta(
        &AuthConfig::default(),
        None,
        |meta| {
            let mut meta = account.install(meta);
            if cache {
                meta.enable_idempotency(
                    Arc::new(crate::idempotency::IdempotencyCache::new()),
                    std::time::Duration::from_secs(60),
                );
            }
            meta
        },
    )
    .await;
    (super::create_router(Arc::clone(&state)), (state, store))
}

/// `params` keyed with `key`.
fn keyed(mut params: Value, key: &str) -> Value {
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    params["_meta"] = meta;
    params
}

/// Run `params` (a keyed `name` call) twice on `router`. The first run must
/// reach the capture peer once and succeed; the replay must equal it apart
/// from `id`, with nothing sent again.
async fn assert_replay_served(
    row: &str,
    router: &axum::Router,
    account: &CapabilityAccount,
    name: &str,
    params: Value,
) {
    let first = send(router, "tools/call", name, params.clone()).await;
    assert!(
        first.get("error").is_none() && first.pointer("/result/isError") != Some(&json!(true)),
        "premise: the call succeeded: {first}"
    );
    assert!(
        first
            .pointer("/result/content/0/text")
            .and_then(Value::as_str)
            .is_some_and(|text| !text.is_empty()),
        "premise: the run carries the peer's payload: {first}"
    );
    assert_eq!(
        account.peer_requests(),
        1,
        "premise: the run reached the peer once"
    );
    let again = send(router, "tools/call", name, params).await;
    let mut masked = (again.clone(), first);
    masked.0["id"] = Value::Null;
    masked.1["id"] = Value::Null;
    assert_eq!(
        masked.0, masked.1,
        "{row}: the replay differs from the run: {again}"
    );
    assert_eq!(account.peer_requests(), 1, "{row}: the replay was sent");
}

/// P8s (MIK-8451.PLAN.1): a keyed `gateway_execute` on a capability whose
/// account is an explicit `shared` descriptor. The account dispatches under
/// the gateway's static credential, with no per-caller binding, and never
/// lapses, so the stored plan replay is served: the same answer, nothing
/// sent again. Production config (idempotency cache armed). Red at
/// 19ca01f07: the plan walk demanded a per-caller mint and refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p8s_a_shared_account_plan_replay_is_served() {
    let account = CapabilityAccount::start_shared().await;
    let (router, _keep) = capability_router(&account, true).await;
    let params = json!({"name": "gateway_execute",
        "arguments": {"tool": format!("{CAPABILITY_SERVER}:{CAPABILITY_TOOL}"), "arguments": {}}});
    assert_replay_served(
        "P8s",
        &router,
        &account,
        "gateway_execute",
        keyed(params, "p8s"),
    )
    .await;
}

/// P8s-single (MIK-8451.PLAN.2): the single-call twin, with the idempotency
/// cache unarmed. A shared account needs no liveness proof, so the retained
/// result is served at admission. Red at 19ca01f07, where only the cache
/// fallback (STORED.2 FIX 1b) served it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p8s_single_a_shared_account_replay_is_served_without_the_cache() {
    let account = CapabilityAccount::start_shared().await;
    let (router, _keep) = capability_router(&account, false).await;
    let params = json!({"name": "gateway_invoke",
        "arguments": {"server": CAPABILITY_SERVER, "tool": CAPABILITY_TOOL, "arguments": {}}});
    assert_replay_served(
        "P8s-single",
        &router,
        &account,
        "gateway_invoke",
        keyed(params, "p8s-single"),
    )
    .await;
}

/// P8u (MIK-8451, mUndeclared): a capability naming an account no descriptor
/// declares, registered with no registry to check it against. Dispatch is
/// the only refusal (`account_strategies.rs` `declared_installed`), so the
/// live call refuses before the peer, and a keyed replay of it gives the
/// same refusal: nothing was stored to serve, and nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p8u_an_undeclared_account_refuses_live_and_on_replay() {
    let account = CapabilityAccount::start_undeclared().await;
    let (router, _keep) = capability_router(&account, true).await;
    let params = keyed(
        json!({"name": "gateway_execute",
            "arguments": {"tool": format!("{CAPABILITY_SERVER}:{CAPABILITY_TOOL}"),
                "arguments": {}}}),
        "p8u",
    );
    let live = send(&router, "tools/call", "gateway_execute", params.clone()).await;
    assert!(
        live.to_string()
            .contains("which is not a key in accounts.descriptors"),
        "P8u: the live call was not refused as undeclared: {live}"
    );
    let again = send(&router, "tools/call", "gateway_execute", params).await;
    let mut masked = (again.clone(), live);
    masked.0["id"] = Value::Null;
    masked.1["id"] = Value::Null;
    assert_eq!(
        masked.0, masked.1,
        "P8u: the replay differs from the live refusal: {again}"
    );
    assert_eq!(account.peer_requests(), 0, "P8u: a call reached the peer");
}

#[path = "stored_read_capability_cooldown_tests.rs"]
mod cooldown;

// MIK-8407: a capability hot-re-bound to another account.
mod rebind;
