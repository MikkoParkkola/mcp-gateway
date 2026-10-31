// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8154.LEASE.1 rows (test plan r1.1): the direct route takes the shared
//! execution lease (matrix gap 11, Direct x Lease). Each row is red on the
//! release tip unless its doc says CONTROL.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::direct_guards_fixture::{
    Answer, Fx, fixture_built, fixture_built_on, post_direct, post_meta_invoke, schema_off,
};

/// The store's mismatch refusal as both routes put it on the wire.
const MISMATCH: &str =
    "JSON-RPC error 409: Idempotency key belongs to another execution or representation";
fn calls(fx: &Fx) -> usize {
    fx.calls.load(Ordering::SeqCst)
}

fn message(body: &Value) -> &str {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// A backend whose `tools/call` signals `entered`, then waits for `gate`.
struct Held {
    entered: Arc<tokio::sync::Notify>,
    gate: Arc<tokio::sync::Notify>,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Held {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let body = if method == "tools/list" {
            json!({"tools": [{"name": "read", "inputSchema": {"type": "object"}}]})
        } else {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            self.gate.notified().await;
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
        };
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            body,
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Which route sends a keyed `read` on `alpha`.
#[derive(Clone, Copy, Debug)]
enum Via {
    Invoke,
    Direct,
}

async fn keyed(fx: &Fx, via: Via, key: &str) -> Value {
    keyed_on(fx, via, "alpha", key).await
}

/// [`keyed`] on `server` (`alpha-pt` is the passthrough backend).
async fn keyed_on(fx: &Fx, via: Via, server: &str, key: &str) -> Value {
    match via {
        Via::Invoke => {
            post_meta_invoke(fx, "k-std", server, "read", json!({}), Some(key), None)
                .await
                .1
        }
        Via::Direct => {
            post_direct(fx, server, "k-std", "read", json!({}), Some(key), None)
                .await
                .1
        }
    }
}

/// `first` under key K, held at the backend; then `second` under K. Returns
/// (the second's answer, the backend's `tools/call` count).
async fn cross_route(first: Via, second: Via) -> (Value, usize) {
    let (entered, gate) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    let count = Arc::new(AtomicUsize::new(0));
    let held = Held {
        entered: Arc::clone(&entered),
        gate: Arc::clone(&gate),
        calls: Arc::clone(&count),
    };
    let fx = Arc::new(fixture_built_on(Arc::new(held), |meta| meta).await);
    let shared = Arc::clone(&fx);
    let held_call = tokio::spawn(async move { keyed(&shared, first, "lease-k").await });
    tokio::time::timeout(std::time::Duration::from_secs(30), entered.notified())
        .await
        .expect("the first call reached the held backend");
    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        keyed(&fx, second, "lease-k"),
    )
    .await;
    gate.notify_waiters();
    gate.notify_one();
    let answer = answer.expect("the second call was answered while the first was held");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), held_call).await;
    (answer, count.load(Ordering::SeqCst))
}

/// The 7a idempotency guard's in-flight refusal, shared by `/mcp` and the
/// direct route (keyed on the idempotency key plus the credential).
const DUPLICATE: &str = "Duplicate request in progress for key:";

/// L1 CONTROL: a direct call under K while `gateway_invoke` of the same
/// target under K is in flight is refused at 7a, which both routes share;
/// the backend runs once. Green on the tip (probe 8154-probeA) and unchanged
/// by the fix, which adds the lease after 7a.
#[tokio::test]
async fn l1_direct_call_meets_an_in_flight_invoke_of_the_same_target() {
    let (answer, runs) = cross_route(Via::Invoke, Via::Direct).await;
    assert!(message(&answer).contains(DUPLICATE), "l1: {answer}");
    assert_eq!(runs, 1, "l1: the backend ran {runs} times");
}

/// L2: the reverse of L1. On `/mcp` the execution lease (`admit_meta_sync`)
/// runs before the meta route's idempotency cache, so once the held direct
/// call holds a lease the store answers first, with its mismatch. On the tip
/// the direct call held no lease, and the cache refused it as a duplicate.
#[tokio::test]
async fn l2_invoke_meets_an_in_flight_direct_call() {
    let (answer, runs) = cross_route(Via::Direct, Via::Invoke).await;
    assert_eq!(message(&answer), MISMATCH, "l2: {answer}");
    assert_eq!(runs, 1, "l2: the backend ran {runs} times");
}

/// L3 CONTROL: a completed `/mcp` result retried on `/mcp/{name}` under the
/// same key is a hit in the idempotency cache the two routes share, which
/// answers before 7b (design L3: a cache hit skips the lease): replayed, and
/// the backend runs once. Green on the tip and unchanged by the fix.
#[tokio::test]
async fn l3_completed_invoke_then_direct_retry_replays_once() {
    let fx = fixture_built(Answer::Ok, |meta| meta).await;
    let first = keyed(&fx, Via::Invoke, "lease-k3").await;
    assert!(
        first.get("error").is_none(),
        "premise: the invoke failed: {first}"
    );
    let retry = keyed(&fx, Via::Direct, "lease-k3").await;
    // Each route shapes its own answer; the replay is proven by the count.
    assert!(retry.get("error").is_none(), "l3: {retry}");
    assert_eq!(calls(&fx), 1, "l3: the backend ran again");
}

/// U1 CONTROL: an unkeyed direct call is `Unprotected`: it dispatches once.
#[tokio::test]
async fn u1_an_unkeyed_direct_call_dispatches_once() {
    let fx = fixture_built(Answer::Ok, |meta| meta).await;
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", json!({}), None, None).await;
    assert!(body.get("error").is_none(), "u1: {body}");
    assert_eq!(calls(&fx), 1, "u1: dispatched {} times", calls(&fx));
}

/// A modern, keyed, task-augmented `gateway_invoke` of `alpha/read`.
fn task_submit(key: &str) -> Value {
    json!({
        "name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
        "task": {},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "extensions": {"io.modelcontextprotocol/tasks": {}}
            },
            crate::protocol::mrtr::IDEMPOTENCY_KEY_META: key
        }
    })
}

/// L9: a task submit under K whose worker is held at the backend, then a
/// direct call under K: refused with the shared store's mismatch, and the
/// backend runs once. RED: the direct call is outside the store.
#[tokio::test]
async fn l9_direct_call_meets_an_in_flight_task_of_the_same_target() {
    let (entered, gate) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    let count = Arc::new(AtomicUsize::new(0));
    let held = Held {
        entered: Arc::clone(&entered),
        gate: Arc::clone(&gate),
        calls: Arc::clone(&count),
    };
    let fx = fixture_built_on(Arc::new(held), |meta| meta).await;
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_invoke"),
    ];
    let (_, created) = super::direct_guards_fixture::send_with_headers(
        &fx,
        "/mcp",
        "k-std",
        "tools/call",
        task_submit("lease-k9"),
        None,
        &headers,
    )
    .await;
    assert!(
        created.pointer("/result/taskId").is_some(),
        "premise: the task submit was not admitted: {created}"
    );
    tokio::time::timeout(std::time::Duration::from_secs(30), entered.notified())
        .await
        .expect("the task's worker reached the held backend");
    // The held backend blocks every call, so a direct call that reaches it
    // never answers: a second entry is the red outcome, named as such.
    let answer = tokio::select! {
        answer = keyed(&fx, Via::Direct, "lease-k9") => Some(answer),
        () = entered.notified() => None,
        () = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
            panic!("l9: the direct call neither answered nor reached the backend")
        }
    };
    gate.notify_waiters();
    gate.notify_one();
    let answer = answer.unwrap_or_else(|| {
        panic!(
            "l9: the direct call reached the held backend (calls {})",
            count.load(Ordering::SeqCst)
        )
    });
    assert_eq!(message(&answer), MISMATCH, "l9: {answer}");
    assert_eq!(count.load(Ordering::SeqCst), 1, "l9: the backend ran twice");
}

/// L0: the direct route admits the operation `gateway_invoke` admits for the
/// same target and arguments, byte for byte, so the two collide in the one
/// store. RED: the tip's direct route admits nothing.
#[tokio::test]
async fn l0_the_direct_route_admits_the_operation_invoke_admits() {
    let fx = fixture_built(Answer::Ok, |meta| meta).await;
    let take = crate::gateway::meta_mcp::admission::take_last_operation;
    take();
    let args = json!({"cmd": "x"});
    post_direct(
        &fx,
        "alpha",
        "k-std",
        "read",
        args.clone(),
        Some("l0-d"),
        None,
    )
    .await;
    let direct = take();
    post_meta_invoke(&fx, "k-std", "alpha", "read", args, Some("l0-i"), None).await;
    let invoke = take();
    assert!(
        direct.is_some(),
        "l0: the direct call admitted no operation"
    );
    assert_eq!(direct, invoke, "l0: the routes admit different operations");
    // Pinned, so the two cannot drift wrong in lockstep.
    assert_eq!(
        direct,
        Some(json!({
            "kind": "backend", "server": "alpha", "tool": "read",
            "arguments": {"cmd": "x"}, "retry": ""
        })),
        "l0: the operation's shape moved"
    );
}

/// MIK-8663 T2(op) (DUPC-6.PR6.4, direct): the `/mcp/{name}` route admits the
/// operation with the gateway directives stripped, the operation
/// `gateway_invoke` admits for the same call. Mutant: the route's
/// `execution_arguments_cow` call removed leaves both in the operation.
#[tokio::test]
async fn l0b_the_direct_operation_strips_the_gateway_directives() {
    let fx = Box::pin(schema_off(fixture_built(Answer::Ok, |meta| meta))).await;
    let take = crate::gateway::meta_mcp::admission::take_last_operation;
    take();
    let args = json!({
        "cmd": "x",
        "_full": true,
        "_claim": {"kind": "found_rows", "count": 1},
    });
    post_direct(
        &fx,
        "alpha",
        "k-std",
        "read",
        args.clone(),
        Some("l0b-d"),
        None,
    )
    .await;
    let routed = take();
    post_meta_invoke(&fx, "k-std", "alpha", "read", args, Some("l0b-i"), None).await;
    let invoke = take();
    assert_eq!(
        routed,
        Some(json!({
            "kind": "backend", "server": "alpha", "tool": "read",
            "arguments": {"cmd": "x"}, "retry": ""
        })),
        "l0b: the routed operation kept a gateway directive"
    );
    assert_eq!(routed, invoke, "l0b: the routes admit different operations");
}

/// MIK-8663 T2(a): on `/mcp/{name}` the names `_full` and `_claim` are the
/// backend's own argument bytes, forwarded as sent.
#[tokio::test]
async fn l0c_the_direct_route_forwards_directive_named_arguments() {
    let fx = Box::pin(schema_off(fixture_built(Answer::Ok, |meta| meta))).await;
    let claim = json!({"kind": "found_rows", "count": 1});
    let args = json!({"cmd": "x", "_full": true, "_claim": claim.clone()});
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", args, None, None).await;
    assert!(body.get("error").is_none(), "l0c: the call failed: {body}");
    let seen = fx.seen.lock().expect("seen lock").last().cloned();
    let arguments = seen.as_ref().map(|params| &params["arguments"]);
    assert_eq!(
        arguments.map(|a| &a["_full"]),
        Some(&json!(true)),
        "l0c: {seen:?}"
    );
    assert_eq!(
        arguments.map(|a| &a["_claim"]),
        Some(&claim),
        "l0c: {seen:?}"
    );
}

/// L8b CONTROL (kills "cancel before dispatch settles"): a direct call under
/// K dropped after admission but before its lease is marked releases the key,
/// so a `gateway_invoke` of the same target under K proceeds and runs.
#[tokio::test]
async fn l8b_a_call_cancelled_before_dispatch_releases() {
    let fx = Arc::new(fixture_built(Answer::Ok, |meta| meta).await);
    // The call is aborted, never released; `_gate` keeps the pair alive to the end of the row.
    let (entered, _gate) = super::backend_handlers::direct_lease_seams::hold_before_mark();
    let shared = Arc::clone(&fx);
    let call = tokio::spawn(async move { keyed(&shared, Via::Direct, "l8b").await });
    tokio::time::timeout(std::time::Duration::from_secs(30), entered.notified())
        .await
        .expect("the direct call reached the point before dispatch");
    call.abort();
    let _ = call.await;
    assert_eq!(
        calls(&fx),
        0,
        "premise: the dropped call reached the backend"
    );
    let after = keyed(&fx, Via::Invoke, "l8b").await;
    assert!(after.get("error").is_none(), "l8b: {after}");
    assert_eq!(calls(&fx), 1, "l8b: the invoke did not run");
}

/// L7a: a direct call under K whose backend asks, and whose question is
/// delivered with a continuation, keeps its lease counted: the backend
/// received round 1 and may have acted, so a `gateway_invoke` of the same
/// target under K is refused rather than run a second time. A refusal of the
/// question, or a failure before dispatch (L7b), still withdraws it.
#[tokio::test]
async fn l7a_a_delivered_question_keeps_the_lease() {
    let fx = fixture_built(Answer::AskOnce, |meta| meta).await;
    // A modern call declaring form elicitation, so the question is delivered.
    let key = json!({"_meta": {crate::protocol::mrtr::IDEMPOTENCY_KEY_META: "l7a"}});
    let (_, asked) = super::direct_continuation_tests::call(&fx, "alpha", None, key).await;
    assert!(
        asked.pointer("/result/requestState").is_some(),
        "premise: the backend's question was not delivered: {asked}"
    );
    let after = keyed(&fx, Via::Invoke, "l7a").await;
    assert_eq!(
        after["error"]["code"], 409,
        "l7a: the invoke was not refused: {after}"
    );
    assert_eq!(calls(&fx), 1, "l7a: the invoke reached the backend again");
}

/// L7b CONTROL (kills "withdraw replaced by settle"): a failure raised before
/// dispatch withdraws the lease likewise.
#[tokio::test]
async fn l7b_a_pre_dispatch_failure_withdraws_the_lease() {
    // `Unreachable` is a connect failure: nothing left the gateway. (A
    // `Transport` failure may have, so it settles as uncertain instead.)
    let fx = fixture_built(Answer::Unreachable, |meta| meta).await;
    let failed = keyed(&fx, Via::Direct, "l7b").await;
    assert!(failed.get("error").is_some(), "premise: {failed}");
    let after = keyed(&fx, Via::Invoke, "l7b").await;
    // Admitted and sent as a never-used key is: the same answer a fresh
    // key gets, which is the unreachable backend's, never the store's.
    let fresh = keyed(&fx, Via::Invoke, "l7b-fresh").await;
    assert_eq!(message(&after), message(&fresh), "l7b: {after}");
    assert_ne!(message(&after), MISMATCH, "l7b: {after}");
}

/// L7c: a direct call that dispatched settles its lease, so a
/// `gateway_invoke` of the same target under K meets the store's mismatch
/// and the backend does not run again. RED: on the tip the store holds
/// nothing and the invoke is answered from the shared cache.
#[tokio::test]
async fn l7c_a_dispatched_call_settles_the_lease() {
    // Both dispatch arms: the sanitized one, and the passthrough one.
    for server in ["alpha", "alpha-pt"] {
        let fx = fixture_built(Answer::Ok, |meta| meta).await;
        let first = keyed_on(&fx, Via::Direct, server, "l7c").await;
        assert!(first.get("error").is_none(), "premise {server}: {first}");
        let after = keyed_on(&fx, Via::Invoke, server, "l7c").await;
        assert_eq!(message(&after), MISMATCH, "l7c {server}: {after}");
        assert_eq!(calls(&fx), 1, "l7c {server}: the backend ran again");
    }
}

/// L8: a direct call dropped after it reached the backend leaves its lease
/// settled as uncertain, never released: a `gateway_invoke` under K meets
/// the store, and the backend runs once. RED: on the tip the cache answers.
#[tokio::test]
async fn l8_a_call_cancelled_after_dispatch_settles() {
    let (entered, gate) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    let count = Arc::new(AtomicUsize::new(0));
    let held = Held {
        entered: Arc::clone(&entered),
        gate: Arc::clone(&gate),
        calls: Arc::clone(&count),
    };
    let fx = Arc::new(fixture_built_on(Arc::new(held), |meta| meta).await);
    let shared = Arc::clone(&fx);
    let call = tokio::spawn(async move { keyed(&shared, Via::Direct, "l8").await });
    tokio::time::timeout(std::time::Duration::from_secs(30), entered.notified())
        .await
        .expect("the direct call reached the held backend");
    call.abort();
    let _ = call.await;
    let after = tokio::select! {
        after = keyed(&fx, Via::Invoke, "l8") => after,
        () = entered.notified() => panic!("l8: the invoke reached the backend again"),
    };
    gate.notify_waiters();
    assert_eq!(message(&after), MISMATCH, "l8: {after}");
    assert_eq!(count.load(Ordering::SeqCst), 1, "l8: the backend ran twice");
}

/// A cache the row holds, so it can age it (a forced 7a miss) while the
/// execution store keeps its entries; and the arming that installs it.
fn held_cache() -> (
    Arc<crate::idempotency::IdempotencyCache>,
    impl FnOnce(crate::gateway::meta_mcp::MetaMcp) -> crate::gateway::meta_mcp::MetaMcp,
) {
    let cache = Arc::new(crate::idempotency::IdempotencyCache::new());
    let installed = Arc::clone(&cache);
    let arm = move |mut meta: crate::gateway::meta_mcp::MetaMcp| {
        meta.enable_idempotency(installed, std::time::Duration::from_secs(300));
        meta
    };
    (cache, arm)
}

/// A signed fixture whose idempotency cache the row holds.
async fn signed_with_cache() -> (Fx, Arc<crate::idempotency::IdempotencyCache>) {
    let (cache, arm) = held_cache();
    let fx =
        super::direct_guards_fixture::fixture_hardened_signed_built(Answer::Ok, true, arm).await;
    (fx, cache)
}

/// A modern, signed, keyed direct `tools/call read` (the hardened posture
/// serves the direct route no legacy `tools/call`).
async fn signed_direct(fx: &Fx, key: &str, cmd: &str, nonce: &str) -> (u16, Value) {
    use crate::protocol::meta::{KEY_CLIENT_CAPABILITIES, KEY_PROTOCOL_VERSION, MODERN_VERSIONS};
    let params = json!({
        "name": "read",
        "arguments": {"cmd": cmd},
        "_meta": {
            KEY_PROTOCOL_VERSION: MODERN_VERSIONS[0],
            KEY_CLIENT_CAPABILITIES: {},
            crate::gateway::meta_mcp::signing::NONCE_META: nonce,
            crate::protocol::mrtr::IDEMPOTENCY_KEY_META: key,
        }
    });
    let (status, body) = super::direct_guards_fixture::send_with_headers(
        fx,
        "/mcp/alpha",
        "k-std",
        "tools/call",
        params,
        None,
        &[
            ("mcp-protocol-version", MODERN_VERSIONS[0]),
            ("mcp-method", "tools/call"),
            ("mcp-name", "read"),
        ],
    )
    .await;
    (status.as_u16(), body)
}

/// Past the cache's 24-hour completed lifetime: a forced 7a miss.
const PAST_THE_CACHE: std::time::Duration = std::time::Duration::from_secs(25 * 60 * 60);

/// The MAC the gateway's v2 signer gives `delivered` (its `result` without
/// `_signature`, its id) under the fixture's key, `nonce` and the timestamp
/// the delivered block names: what a verifier recomputes.
fn expected_sig(delivered: &Value, nonce: &str) -> Value {
    let block = &delivered["result"]["_signature"];
    assert_eq!(block["version"], 2, "a v2 signature block: {delivered}");
    let ts = block["ts"].as_u64().expect("a signing timestamp");
    let id = delivered["id"].as_i64().expect("a numeric request id");
    let mut response = crate::protocol::JsonRpcResponse::success(
        crate::protocol::RequestId::Number(id),
        delivered["result"].clone(),
    );
    crate::security::message_signing::MessageSigner::new(
        super::direct_guards_fixture::SIGNING_KEY
            .as_bytes()
            .to_vec(),
        None,
        block["key_id"].as_str().expect("a key id").to_owned(),
    )
    .sign_json_rpc_response_at(&mut response, Some(nonce), ts)
    .expect("the delivered result signs");
    response.result.expect("a result")["_signature"]["sig"].clone()
}

/// L5 (test plan H1): a 7b refusal gives the 7a reservation back and spends
/// no signing nonce. Under K a settled call, then (7a aged out) the same key
/// for different arguments: refused by the store, twice, never as a
/// duplicate in flight; then the refused call's nonce, on a new key,
/// dispatches. RED: on the tip the store is not consulted and the reused key
/// dispatches.
#[tokio::test]
async fn l5_a_7b_refusal_drops_the_7a_reservation_and_spends_no_nonce() {
    let (fx, cache) = signed_with_cache().await;
    let (status, first) = signed_direct(&fx, "l5", "a", "l5-n1").await;
    assert_eq!(status, 200, "premise: {first}");
    cache.advance_for_test(PAST_THE_CACHE);
    for nonce in ["l5-n2", "l5-n3"] {
        let (_, refused) = signed_direct(&fx, "l5", "b", nonce).await;
        // The second refusal, under the same key, is the store's again and
        // never "Duplicate request in progress": the first refusal's 7a
        // reservation was released when it was dropped.
        assert_eq!(message(&refused), MISMATCH, "l5 {nonce}: {refused}");
        assert_eq!(calls(&fx), 1, "l5 {nonce}: dispatched");
    }
    let (status, fresh) = signed_direct(&fx, "l5-new", "b", "l5-n2").await;
    assert_eq!(
        status, 200,
        "l5: the refused call's nonce was spent: {fresh}"
    );
    assert_eq!(calls(&fx), 2, "l5: the fresh key did not dispatch");
}

/// L6 (test plan M2, G2): a forced 7a miss with a 7b hit replays through the
/// direct route's own delivery. A fresh nonce: no new backend run, signed
/// for this request's nonce, not the stored one's. The stored call's nonce
/// again: refused as a replay, no run. Then the key again: 7a was released
/// before delivery, so no duplicate-in-flight refusal. RED: on the tip the
/// aged-out key dispatches again.
#[tokio::test]
async fn l6_a_forced_7a_miss_with_a_7b_hit_replays_through_direct_delivery() {
    let (fx, cache) = signed_with_cache().await;
    let (status, first) = signed_direct(&fx, "l6", "a", "l6-n1").await;
    assert_eq!(status, 200, "premise: {first}");
    // The verifier itself: a fresh delivery verifies under its own nonce.
    assert_eq!(
        first["result"]["_signature"]["sig"],
        expected_sig(&first, "l6-n1"),
        "premise: the recomputed MAC does not match a fresh delivery"
    );
    cache.advance_for_test(PAST_THE_CACHE);
    let (status, replay) = signed_direct(&fx, "l6", "a", "l6-n2").await;
    assert_eq!(status, 200, "l6 fresh: {replay}");
    assert_eq!(calls(&fx), 1, "l6 fresh: the backend ran again");
    assert_eq!(
        super::backend_handlers::direct_lease_seams::replay_held_7a(),
        Some(false),
        "l6 fresh: the 7a reservation was still held when the replay's delivery began"
    );
    let signature = &replay["result"]["_signature"];
    assert_eq!(
        signature["sig"],
        expected_sig(&replay, "l6-n2"),
        "l6 fresh: the replay does not verify under the gateway key and this nonce"
    );
    assert_eq!(signature["nonce"], "l6-n2", "l6 fresh: {replay}");
    assert_ne!(
        signature["sig"],
        expected_sig(&replay, "l6-n1"),
        "l6 fresh: the replay also verifies under the stored call's nonce"
    );
    let (status, reused) = signed_direct(&fx, "l6", "a", "l6-n1").await;
    assert_eq!(status, 400, "l6 reused nonce: {reused}");
    assert!(reused.get("result").is_none(), "l6 reused nonce: {reused}");
    assert_eq!(calls(&fx), 1, "l6 reused nonce: dispatched");
    let (status, again) = signed_direct(&fx, "l6", "a", "l6-n3").await;
    assert_eq!(status, 200, "l6 again: {again}");
    assert!(!message(&again).contains(DUPLICATE), "l6 again: {again}");
    assert_eq!(calls(&fx), 1, "l6 again: dispatched");
}

/// A backend whose `read` declares `_claim` and `_full` as its own
/// arguments, answering every call at once.
struct Declares {
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Declares {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let body = if method == "tools/list" {
            json!({"tools": [{"name": "read", "inputSchema": {"type": "object", "properties": {
                "cmd": {"type": "string"}, "_claim": {"type": "string"}, "_full": {"type": "string"}
            }}}]})
        } else {
            self.calls.fetch_add(1, Ordering::SeqCst);
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
        };
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            body,
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// L10: on the direct route `_claim` and `_full` are the backend's own
/// arguments, never gateway controls. Two direct calls under K that differ
/// only there are two requests: with 7a aged out, the second is refused by
/// the store, never replayed the first's answer. RED before the direct
/// representation bound the arguments as sent.
#[tokio::test]
async fn l10_backend_arguments_named_like_gateway_controls_stay_distinct() {
    let (cache, arm) = held_cache();
    let count = Arc::new(AtomicUsize::new(0));
    let backend = Declares {
        calls: Arc::clone(&count),
    };
    let fx = fixture_built_on(Arc::new(backend), arm).await;
    for (key, field) in [("l10-claim", "_claim"), ("l10-full", "_full")] {
        let before = count.load(Ordering::SeqCst);
        let first = json!({"cmd": "x", field: "a"});
        let (_, body) = post_direct(&fx, "alpha", "k-std", "read", first, Some(key), None).await;
        assert!(body.get("error").is_none(), "premise {field}: {body}");
        let ran = count.load(Ordering::SeqCst);
        assert_eq!(
            ran,
            before + 1,
            "premise {field}: the backend did not run: {body}"
        );
        cache.advance_for_test(PAST_THE_CACHE);
        let second = json!({"cmd": "x", field: "b"});
        let (_, body) = post_direct(&fx, "alpha", "k-std", "read", second, Some(key), None).await;
        assert_eq!(
            message(&body),
            MISMATCH,
            "l10 {field}: replayed another request: {body}"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            ran,
            "l10 {field}: the backend ran"
        );
        // The other direction: the same request again replays, unrun.
        let same = json!({"cmd": "x", field: "a"});
        let (_, body) = post_direct(&fx, "alpha", "k-std", "read", same, Some(key), None).await;
        assert!(
            body.get("error").is_none(),
            "l10 {field}: the same request: {body}"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            ran,
            "l10 {field}: the same request ran"
        );
    }
}

/// L11: a dispatched call the backend answered with an error settles the
/// lease with that answer, as 7a stores it. With 7a aged out, the retry is
/// replayed the same error, not "Secured execution result is unavailable",
/// and the backend runs once. RED before the failure path settled the lease.
#[tokio::test]
async fn l11_a_dispatched_failure_settles_the_lease_with_its_answer() {
    let (cache, arm) = held_cache();
    // A failed dispatch: the backend's refusal as an error, past dispatch.
    // Both dispatch arms: the sanitized one, and the passthrough one.
    let fx = fixture_built(Answer::FailedWith("l11 backend refusal"), arm).await;
    for (server, key) in [("alpha", "l11"), ("alpha-pt", "l11-pt")] {
        let before = calls(&fx);
        let first = keyed_on(&fx, Via::Direct, server, key).await;
        assert!(first.get("error").is_some(), "premise {server}: {first}");
        cache.advance_for_test(PAST_THE_CACHE);
        let retry = keyed_on(&fx, Via::Direct, server, key).await;
        assert_eq!(
            retry.get("error"),
            first.get("error"),
            "l11 {server}: {retry}"
        );
        assert_eq!(
            calls(&fx),
            before + 1,
            "l11 {server}: the backend ran again"
        );
    }
}
