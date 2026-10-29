// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #3892 rows: a busy managed custody on a REST capability account (and at
//! a per-user mint) answers and audits as the stored read does. A healthy
//! control proves a served call by the loopback capture peer receiving it
//! and the answer carrying no tool error ([`assert_served`]), not by an
//! outer "completed" alone.

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::busy_nonce::{refused_as_replay, signed_fixture, signed_invoke};
use super::{Fx, MARKER};
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

fn keyed_meta(key: &str) -> Value {
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    meta
}

struct CapabilityHarness {
    router: axum::Router,
    state: Arc<super::super::AppState>,
    account: CapabilityAccount,
    _store: crate::gateway::router::tests::FixtureDir,
}

async fn capability_harness(signed: bool) -> CapabilityHarness {
    capability_harness_over(CapabilityAccount::start(false).await, signed).await
}

async fn capability_harness_over(account: CapabilityAccount, signed: bool) -> CapabilityHarness {
    let (state, store) = super::super::tests::meta_fixture::test_router_app_state_with_meta(
        &AuthConfig::default(),
        None,
        |meta| {
            let mut meta = account.install(meta);
            if signed {
                meta.enable_message_signing(
                    crate::security::message_signing::MessageSigner::new(
                        b"capability-busy-signing-secret-at-least-32-bytes".to_vec(),
                        None,
                        "capability-busy".into(),
                    ),
                    std::time::Duration::from_secs(300),
                    true,
                );
            }
            meta
        },
    )
    .await;
    let router = super::super::create_router(Arc::clone(&state));
    CapabilityHarness {
        router,
        state,
        account,
        _store: store,
    }
}

async fn body_of(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// POST as alice, whose verified identity rides in as a request extension.
async fn send_as(router: &axum::Router, method: &str, name: &str, params: Value) -> Value {
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
    body_of(router.clone().oneshot(request).await.expect("an answer")).await
}

/// A signed capability `gateway_invoke`: the nonce rides in `arguments`,
/// as the busy-nonce rows send it for the per-user backend.
async fn signed_capability_invoke(harness: &CapabilityHarness, nonce: &str) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": {"server": CAPABILITY_SERVER, "tool": CAPABILITY_TOOL,
            "arguments": {}, "nonce": nonce},
        "_meta": modern_meta(),
    }});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request.extensions_mut().insert(CapabilityAccount::alice());
    body_of(
        harness
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("an answer"),
    )
    .await
}

fn capability_task_params(key: &str) -> Value {
    json!({"name": "gateway_invoke",
        "arguments": {"server": CAPABILITY_SERVER, "tool": CAPABILITY_TOOL, "arguments": {}},
        "task": {}, "_meta": keyed_meta(key)})
}

fn capability_live_params() -> Value {
    json!({"name": "gateway_invoke",
        "arguments": {"server": CAPABILITY_SERVER, "tool": CAPABILITY_TOOL, "arguments": {}},
        "_meta": modern_meta()})
}

async fn capability_live(harness: &CapabilityHarness) -> Value {
    send_as(
        &harness.router,
        "tools/call",
        "gateway_invoke",
        capability_live_params(),
    )
    .await
}

async fn capability_tasked(harness: &CapabilityHarness, key: &str) -> Value {
    send_as(
        &harness.router,
        "tools/call",
        "gateway_invoke",
        capability_task_params(key),
    )
    .await
}

async fn task_get(harness: &CapabilityHarness, id: &str) -> Value {
    send_as(
        &harness.router,
        "tasks/get",
        id,
        json!({"taskId": id, "_meta": modern_meta()}),
    )
    .await
}

fn task_id(made: &Value, row: &str) -> String {
    made.pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{row} premise: a task was made: {made}"))
        .to_owned()
}

fn committed_tasks(harness: &CapabilityHarness) -> usize {
    harness
        .state
        .task_executor
        .service
        .store
        .committed_count_for_test()
}

/// The settled wire form from the store: waiting on it makes no stored
/// read, so custody-read counts stay attributable to the task itself.
async fn settled_wire(harness: &CapabilityHarness, id: &str, row: &str) -> Value {
    let store = &harness.state.task_executor.service.store;
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let status = store.status_for_test(id);
        if matches!(
            status,
            Some(
                crate::protocol::tasks::TaskStatus::Completed
                    | crate::protocol::tasks::TaskStatus::Failed
                    | crate::protocol::tasks::TaskStatus::Cancelled
            )
        ) {
            break;
        }
        assert!(
            std::time::Instant::now() < bound,
            "{row}: the task never settled: {status:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let digest = store
        .owner_digest_for_test(id)
        .expect("the task has an owner");
    let committed = store.get(&digest, id).expect("the settled task reads");
    serde_json::to_value(committed.task.wire()).expect("JSON")
}

/// A served capability call (#3892): the loopback capture peer received a
/// request since `before`, and the answer carries no tool error.
fn assert_served(harness: &CapabilityHarness, before: usize, reply: &Value, row: &str) {
    assert!(
        harness.account.peer_requests() > before,
        "{row}: the capture peer received no request: {reply}"
    );
    assert!(
        !reply.to_string().contains("\"isError\":true"),
        "{row}: the call was answered a tool error: {reply}"
    );
}

/// A finished capability task, its stored result served once.
async fn finished_capability_task(harness: &CapabilityHarness, key: &str) -> String {
    let before = harness.account.peer_requests();
    let made = capability_tasked(harness, key).await;
    let id = task_id(&made, "capability setup");
    let settled = settled_wire(harness, &id, "capability setup").await;
    assert_eq!(
        settled.get("status"),
        Some(&json!("completed")),
        "premise: the capability task completes while healthy: {settled}"
    );
    let got = task_get(harness, &id).await;
    assert!(
        got.get("error").is_none() && got.pointer("/result/status") == Some(&json!("completed")),
        "premise: the stored result is served once: {got}"
    );
    assert_served(harness, before, &got, "capability setup");
    id
}

fn assert_retryable(reply: &Value, row: &str) {
    assert_eq!(
        reply.pointer("/error/code"),
        Some(&json!(-32603)),
        "{row}: {reply}"
    );
    assert_eq!(
        reply.pointer("/error/message"),
        Some(&json!("temporarily unavailable, retry")),
        "{row}: the shared transient message: {reply}"
    );
    assert_eq!(
        reply.pointer("/error/data/retryable"),
        Some(&json!(true)),
        "{row}: retryable: {reply}"
    );
}

/// The error object with every per-call trace id replaced by one
/// placeholder, as the order twins mask it: two calls never share one.
fn error_masked(body: &Value) -> String {
    const UUID_LEN: usize = 36;
    let text = body.get("error").map(Value::to_string).unwrap_or_default();
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find("gw-") {
        let after = &rest[at + 3..];
        let is_uuid = after.len() >= UUID_LEN
            && after[..UUID_LEN]
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == '-');
        out.push_str(&rest[..at + 3]);
        if is_uuid {
            out.push_str("<trace>");
            rest = &after[UUID_LEN..];
        } else {
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

fn assert_one_transient_refusal(harness: &CapabilityHarness, before: usize, row: &str) {
    let reasons = harness.account.idp_refusal_reasons_for_test();
    assert_eq!(
        reasons.len() - before,
        1,
        "{row}: exactly one idp_refuse: {reasons:?}"
    );
    assert!(
        reasons
            .last()
            .is_some_and(|reason| reason.contains("transient")),
        "{row}: the idp_refuse reason says transient: {reasons:?}"
    );
}

/// R1: live and stored capability answers under a busy custody are the
/// same sealed retryable error, each costing one custody read and one
/// transient `idp_refuse`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r1_a_capability_busy_live_and_stored_answer_the_same_retryable() {
    let harness = capability_harness(false).await;
    let id = finished_capability_task(&harness, "s3892-r1").await;
    harness.account.fail_custody_for_test(true);

    let reads = harness.account.resolves();
    let refusals = harness.account.idp_refusal_reasons_for_test().len();
    let live = capability_live(&harness).await;
    assert_retryable(&live, "R1 live");
    assert_eq!(
        harness.account.resolves() - reads,
        1,
        "R1 live: exactly one custody read"
    );
    assert_one_transient_refusal(&harness, refusals, "R1 live");

    let reads = harness.account.resolves();
    let refusals = harness.account.idp_refusal_reasons_for_test().len();
    let stored = task_get(&harness, &id).await;
    assert_retryable(&stored, "R1 stored");
    assert_eq!(
        error_masked(&stored),
        error_masked(&live),
        "R1: byte-equal errors with the id and trace masked: stored {stored} live {live}"
    );
    assert_eq!(
        harness.account.resolves() - reads,
        1,
        "R1 stored: exactly one custody read"
    );
    assert_one_transient_refusal(&harness, refusals, "R1 stored");
}

/// R2: the signed twin. A mint-time Busy refused the call before
/// anything was released (that is what makes it retryable), so its
/// nonce is refunded and the same signed request serves after recovery.
/// The third send is the control: a nonce spent serving cannot replay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r2_a_signed_capability_mint_busy_gives_its_nonce_back() {
    let harness = capability_harness(true).await;
    harness.account.fail_custody_for_test(true);
    let busy = signed_capability_invoke(&harness, "s3892-r2-n1").await;
    assert_retryable(&busy, "R2 busy");

    harness.account.fail_custody_for_test(false);
    let peer = harness.account.peer_requests();
    let resent = signed_capability_invoke(&harness, "s3892-r2-n1").await;
    assert!(
        !refused_as_replay(&resent),
        "R2: the nonce was kept spent after the busy mint refused the call: {resent}"
    );
    assert!(
        resent.get("error").is_none() && resent.get("result").is_some(),
        "R2: the same signed request is served after recovery: {resent}"
    );
    assert_served(&harness, peer, &resent, "R2 recovery");

    let replay = signed_capability_invoke(&harness, "s3892-r2-n1").await;
    assert!(
        refused_as_replay(&replay),
        "R2 control: a nonce that served is refused as a replay: {replay}"
    );
}

fn per_user_refusal_reasons(fx: &Fx) -> Vec<String> {
    std::fs::read_to_string(&fx.audit_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry["action"] == "idp_refuse")
        .map(|entry| entry["reason"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// R3 (MIK-8428 SETTLE.6 wording): a per-user view read succeeds and the
/// mint's custody read is busy. The signed live call answers the shared
/// retryable error, costs two custody reads in total (one view + one
/// mint), writes one transient `idp_refuse`, and preserves its nonce.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r3_a_per_user_mint_time_busy_is_retryable_once_and_refunds_the_nonce() {
    let fx = signed_fixture().await;
    fx.gateway.fail_custody_after_for_test(1);
    let reads = fx.gateway.resolves();
    let refusals = per_user_refusal_reasons(&fx).len();
    let live = signed_invoke(&fx, "s3892-r3-n1").await;

    assert_retryable(&live, "R3 live");
    assert_eq!(
        fx.gateway.resolves() - reads,
        2,
        "R3: exactly two custody reads in total: one view read plus one mint read"
    );
    let reasons = per_user_refusal_reasons(&fx);
    assert_eq!(
        reasons.len() - refusals,
        1,
        "R3: exactly one idp_refuse: {reasons:?}"
    );
    assert!(
        reasons
            .last()
            .is_some_and(|reason| reason.contains("transient")),
        "R3: the idp_refuse reason says transient: {reasons:?}"
    );

    fx.gateway.fail_custody_for_test(false);
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let resent = signed_invoke(&fx, "s3892-r3-n1").await;
    assert!(
        !refused_as_replay(&resent),
        "R3: the nonce was kept spent after the busy mint refused the call: {resent}"
    );
    assert!(
        resent.to_string().contains(MARKER),
        "R3: the same signed request is served after recovery: {resent}"
    );
}

/// R4: a busy capability is answered at task intake. It creates and
/// holds nothing, so the identical keyed call makes its task once the
/// custody recovers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_a_busy_capability_task_is_refused_at_intake_without_holding_its_key() {
    let harness = capability_harness(false).await;
    harness.account.fail_custody_for_test(true);
    let reads = harness.account.resolves();
    let held = committed_tasks(&harness);
    let busy = capability_tasked(&harness, "s3892-r4").await;

    assert_retryable(&busy, "R4 busy");
    assert!(
        busy.pointer("/result/taskId").is_none(),
        "R4: no task was handed back: {busy}"
    );
    assert_eq!(committed_tasks(&harness), held, "R4: no task was created");
    assert_eq!(
        harness.account.resolves() - reads,
        1,
        "R4: exactly one custody read at intake"
    );

    harness.account.fail_custody_for_test(false);
    let resent = capability_tasked(&harness, "s3892-r4").await;
    let id = task_id(&resent, "R4");
    let settled = settled_wire(&harness, &id, "R4").await;
    assert_eq!(
        settled.get("status"),
        Some(&json!("completed")),
        "R4: the same keyed call completes after recovery: {settled}"
    );
    let got = task_get(&harness, &id).await;
    assert!(
        got.get("error").is_none() && got.pointer("/result/status") == Some(&json!("completed")),
        "R4: the recovered task's output is served: {got}"
    );
}

/// R4 control: the healthy path has two separately attributable custody
/// reads: the intake account view and the worker mint. Waiting in the
/// store rather than by `tasks/get` keeps a stored-read view out of this
/// count.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_control_a_healthy_capability_task_reads_custody_at_intake_and_in_the_worker() {
    let harness = capability_harness(false).await;
    let reads = harness.account.resolves();
    let peer = harness.account.peer_requests();
    let made = capability_tasked(&harness, "s3892-r4-healthy").await;
    let id = task_id(&made, "R4 control");
    let settled = settled_wire(&harness, &id, "R4 control").await;
    assert_eq!(
        settled.get("status"),
        Some(&json!("completed")),
        "R4 control premise: the healthy task completes: {settled}"
    );
    assert_eq!(
        harness.account.resolves() - reads,
        2,
        "R4 control: exactly two custody reads: one intake view plus one worker mint"
    );
    let got = task_get(&harness, &id).await;
    assert!(
        got.get("error").is_none() && got.pointer("/result/status") == Some(&json!("completed")),
        "R4 control: the completed task's output is served: {got}"
    );
    assert_served(&harness, peer, &got, "R4 control");
}

/// R5 (parity; MIK-8392 STORED.2 site 5 and E9, a reviewed departure from
/// #3892's interim row that served the stored task): under a busy custody
/// the repeated keyed task call answers as the live call does, the same
/// sealed retryable error byte for byte (id and trace masked) with exactly
/// the live call's one transient `idp_refuse`, and serves no stored output.
/// The key stays usable: after recovery the same call serves the stored task.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r5_a_busy_repeated_capability_task_answers_as_the_live_call() {
    let harness = capability_harness(false).await;
    let id = finished_capability_task(&harness, "s3892-r5").await;
    harness.account.fail_custody_for_test(true);

    let refusals = harness.account.idp_refusal_reasons_for_test().len();
    let live = capability_live(&harness).await;
    assert_retryable(&live, "R5 live");
    assert_one_transient_refusal(&harness, refusals, "R5 live");

    let refusals = harness.account.idp_refusal_reasons_for_test().len();
    let repeated = capability_tasked(&harness, "s3892-r5").await;
    assert_retryable(&repeated, "R5 repeat");
    assert_eq!(
        error_masked(&repeated),
        error_masked(&live),
        "R5: the repeat is not the live answer: repeat {repeated} live {live}"
    );
    assert_one_transient_refusal(&harness, refusals, "R5 repeat");
    assert!(
        repeated.get("result").is_none(),
        "R5: the stored task was served while custody is busy: {repeated}"
    );

    harness.account.fail_custody_for_test(false);
    let recovered = capability_tasked(&harness, "s3892-r5").await;
    assert_eq!(
        recovered.pointer("/result/taskId"),
        Some(&json!(id)),
        "R5: after recovery the same key serves the stored task: {recovered}"
    );
}

/// R6 (MIK-8428 Case A, RESIDUAL): the intake view succeeds, then the
/// worker's mint meets Busy. The task settles with the shared
/// retryable error — that half is fixed. Releasing the idempotency
/// reservation as pre-send is NOT: the repeat is decided by admission
/// (`BeginOutcome::Existing`) before any settle classification runs,
/// so the same keyed call still replays the stale failed task after
/// recovery. This row pins today's behaviour as the executable
/// statement of that residual; MIK-8428 Case A owns the release.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r6_a_worker_mint_busy_settles_retryable_but_still_holds_its_key() {
    let harness = capability_harness(false).await;
    harness.account.fail_custody_after_for_test(1);
    let made = capability_tasked(&harness, "s3892-r6").await;
    let id = task_id(&made, "R6");
    let settled = settled_wire(&harness, &id, "R6").await;

    assert_eq!(
        settled.get("status"),
        Some(&json!("failed")),
        "R6: the worker-busy task settles as failed: {settled}"
    );
    assert_eq!(
        settled.pointer("/error/code"),
        Some(&json!(-32603)),
        "R6: {settled}"
    );
    assert_eq!(
        settled.pointer("/error/message"),
        Some(&json!("temporarily unavailable, retry")),
        "R6: the shared transient message: {settled}"
    );
    assert_eq!(
        settled.pointer("/error/data/retryable"),
        Some(&json!(true)),
        "R6: retryable: {settled}"
    );

    // RESIDUAL (MIK-8428 Case A): the reservation is not released as
    // pre-send, so the same-key retry after recovery is answered with
    // the SAME failed task instead of running fresh. When Case A
    // lands, this half flips to a new completed task.
    harness.account.fail_custody_for_test(false);
    let resent = capability_tasked(&harness, "s3892-r6").await;
    let retry_id = task_id(&resent, "R6 retry");
    assert_eq!(
        retry_id, id,
        "R6 residual: the same-key retry replays the stale failed task (MIK-8428 Case A): {resent}"
    );
    let retried = settled_wire(&harness, &retry_id, "R6 retry").await;
    assert_eq!(
        retried.get("status"),
        Some(&json!("failed")),
        "R6 residual: the replayed task is still the failed one: {retried}"
    );
}

/// R7 (#3892, lead ruling): a busy custody at RELEASE is not a transient. The
/// refresh before it may already have refreshed or rotated the grant with
/// the provider, an effect that spends the nonce witness, so the signed call
/// answers the plain refusal (no retry data) and its re-send is refused as a
/// replay. The grant is seeded expired, so the refresh really runs with the
/// provider before the release meets Busy. Mutant: the release site mapped
/// back to the typed Busy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r7_a_release_busy_is_not_retryable_and_keeps_the_nonce_spent() {
    let harness = capability_harness_over(CapabilityAccount::start_expired().await, true).await;
    harness.account.fail_release_for_test();
    let refreshed = harness.account.refreshes();
    let refused = signed_capability_invoke(&harness, "s3892-r7-n1").await;
    assert!(
        refused.get("error").is_some(),
        "R7 premise: a release-site busy refuses the call: {refused}"
    );
    assert!(
        harness.account.refreshes() > refreshed,
        "R7 premise: the expired grant was refreshed before the release: {refused}"
    );
    assert!(
        refused.pointer("/error/data/retryable").is_none(),
        "R7: a release-site busy must not be answered retryable: {refused}"
    );

    harness.account.fail_custody_for_test(false);
    let resent = signed_capability_invoke(&harness, "s3892-r7-n1").await;
    assert!(
        refused_as_replay(&resent),
        "R7: the nonce was given back after a release-site busy: {resent}"
    );
}

/// R8 (#3892, the refund control for R7): a busy custody at REFRESH is
/// refused at admission before the refresh runs, so nothing changed: the
/// signed call answers the shared retryable error and the same signed
/// request is served after recovery. Mutant: the refresh site mapped to
/// a plain refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r8_a_refresh_busy_is_retryable_and_gives_its_nonce_back() {
    let harness = capability_harness(true).await;
    harness.account.fail_refresh_for_test();
    let busy = signed_capability_invoke(&harness, "s3892-r8-n1").await;
    assert_retryable(&busy, "R8 busy");

    harness.account.fail_custody_for_test(false);
    let peer = harness.account.peer_requests();
    let resent = signed_capability_invoke(&harness, "s3892-r8-n1").await;
    assert!(
        !refused_as_replay(&resent),
        "R8: the nonce was kept spent after a refresh-site busy: {resent}"
    );
    assert!(
        resent.get("error").is_none() && resent.get("result").is_some(),
        "R8: the same signed request is served after recovery: {resent}"
    );
    assert_served(&harness, peer, &resent, "R8 recovery");
}

/// Gap (residual owned by MIK-8428; lead ruling on #3892): the direct
/// `/mcp/{backend}` route answers a mint-time busy custody through its
/// account refusal (`direct_preflight.rs` -> `direct_refusal`,
/// `router/accounts/offer.rs`): HTTP 403, JSON-RPC -32003, with the
/// transient text. A retryable state is labelled forbidden, so a client
/// does not retry it: availability only, never a wrong grant. The direct
/// route has no stored twin, so its status mapping was left out of #3892.
/// This row pins today's answer so a change to it is seen.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gap_direct_route_labels_a_mint_busy_forbidden() {
    let fx = super::fixture().await;
    fx.gateway.fail_custody_for_test(true);
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": super::TOOL, "arguments": {"folder": "inbox"},
            "_meta": modern_meta()}});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{}", super::BACKEND))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", super::KEY))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", super::TOOL)
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    let response = fx.router.clone().oneshot(request).await.expect("an answer");
    let status = response.status();
    let answer = body_of(response).await;
    assert_eq!(
        status,
        axum::http::StatusCode::FORBIDDEN,
        "gap: the direct route's mint busy status changed: {answer}"
    );
    assert_eq!(
        answer.pointer("/error/code"),
        Some(&json!(-32003)),
        "gap: the direct route's mint busy code changed: {answer}"
    );
    assert_eq!(
        answer.pointer("/error/message").and_then(Value::as_str),
        Some("JSON-RPC error -32603: temporarily unavailable, retry"),
        "gap: the direct route's mint busy text changed: {answer}"
    );
}

/// Gap (residual owned by MIK-8428; lead ruling on #3892): a request the
/// gateway forwards under the caller's credential (`prompts/get` through
/// `caller_forward.rs`) answers a mint-time busy custody with -32603 and
/// the transient text but without the retry data, because the forwarder
/// keeps only the code and message. It has no stored twin; this row pins
/// today's answer so a change to it is seen.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gap_caller_forward_drops_retry_data() {
    let fx = super::fixture().await;
    fx.gateway.fail_custody_for_test(true);
    let name = format!("{}/any_prompt", super::BACKEND);
    let answer = super::send(
        &fx,
        "prompts/get",
        &name,
        json!({"name": name, "_meta": modern_meta()}),
    )
    .await;
    assert_eq!(
        answer.pointer("/error/code"),
        Some(&json!(-32603)),
        "gap: the forwarded mint busy code changed: {answer}"
    );
    assert_eq!(
        answer.pointer("/error/message").and_then(Value::as_str),
        Some("JSON-RPC error -32603: temporarily unavailable, retry"),
        "gap: the forwarded mint busy text changed: {answer}"
    );
    assert!(
        answer.pointer("/error/data/retryable").is_none(),
        "gap: the forwarder now carries the retry data (update MIK-8428): {answer}"
    );
}

#[path = "capability_recheck_busy_tests.rs"]
mod recheck_busy;
#[path = "stored_read_capability_busy_repeat_tests.rs"]
mod repeat;
