// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8353 slice 3d-2 (NONCEFX.11, K6): on hardened, signed stdio a task
//! call the task surface refuses (`stdio_tasks::task_intent`) took no key,
//! lease or task, so it gives its nonce back with the refund witness; after
//! X14 consumed a grant the nonce stays spent.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::owner2_stdio_tasks::{BACKEND, TOOL, backend_listing, dispatch, fixture_on_with};
use crate::config::SurfacedToolConfig;

const REPLAY: &str = "Nonce replay detected";
const NO_KEY: &str = "task creation requires an idempotency key";

/// The hardened, signed stdio fixture surfacing `echo` listed with
/// `annotations` (as `route_matrix_stdio_tasks` builds it).
async fn signed_listing(annotations: Value) -> super::owner2_stdio_tasks::Fixture {
    let served = backend_listing(json!([{
        "name": TOOL,
        "inputSchema": {"type": "object"},
        "annotations": annotations
    }]))
    .await;
    Box::pin(fixture_on_with(served, None, |config| {
        config.server.modern_protocol = true;
        config.security.posture = crate::security::SecurityPosture::Hardened;
        config.security.hardened.private_backends = vec![BACKEND.to_string()];
        let signing = &mut config.security.message_signing;
        signing.enabled = true;
        signing.shared_secret = "s3d2-stdio-intent-secret-0123456789abcdef".to_string();
        signing.require_nonce = true;
        signing.replay_window = 300;
        signing.key_id = "s3d2-stdio".to_string();
        config.meta_mcp.surfaced_tools = vec![SurfacedToolConfig {
            server: BACKEND.to_string(),
            tool: TOOL.to_string(),
        }];
    }))
    .await
}

/// A task-augmented, signed `tools/call` of the surfaced `echo` under
/// `nonce`, keyed by `key` when given, with `extra` merged into its params.
fn task_call(id: u64, nonce: &str, key: Option<&str>, extra: Value) -> Value {
    use crate::gateway::meta_mcp::signing::NONCE_META;
    let mut params = json!({
        "name": TOOL,
        "arguments": {},
        "task": {},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "elicitation": {"form": {}},
                "extensions": {"io.modelcontextprotocol/tasks": {}}
            },
            NONCE_META: nonce,
        },
    });
    if let Some(key) = key {
        params["_meta"]["io.mcp-gateway/idempotency-key"] = json!(key);
    }
    if let (Some(params), Value::Object(extra)) = (params.as_object_mut(), extra) {
        params.extend(extra);
    }
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params})
}

fn message(body: &Value) -> String {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// K6-R: a harmless surfaced tool on a warm catalogue (X14 asks nothing). A
/// task call with no idempotency key is refused by the task surface, having
/// taken nothing. The nonce comes back: send 2 meets the same refusal; send 3
/// with a key is served; send 4 is a replay. Red on base at send 2. Mutant
/// mK6-ask: the give-back at the refusal removed.
#[tokio::test]
async fn a_stdio_task_intent_refusal_gives_the_nonce_back() {
    const NONCE: &str = "s3d2-k6-nonce-0001";
    let fixture = signed_listing(json!({"destructiveHint": false, "readOnlyHint": true})).await;
    let backend =
        (fixture.meta.events_backend_registry().get(BACKEND)).expect("the backend is registered");
    backend
        .get_tools()
        .await
        .expect("the backend lists its tools");
    let committed = fixture.tasks.service.store.committed_count_for_test();

    for (send, id) in [(1, 1), (2, 2)] {
        let refused = dispatch(&fixture, task_call(id, NONCE, None, json!({}))).await;
        assert!(
            message(&refused).contains(NO_KEY),
            "send {send}: the task surface's refusal (at send 2: the nonce was kept): {refused}"
        );
    }
    assert_eq!(
        fixture.tasks.service.store.committed_count_for_test(),
        committed,
        "premise: no refusal committed a task"
    );
    assert_eq!(fixture.rounds.load(Ordering::SeqCst), 0, "premise: unsent");

    let served = dispatch(&fixture, task_call(3, NONCE, Some("k6-a"), json!({}))).await;
    assert!(
        served.pointer("/result/taskId").is_some(),
        "send 3 under the given-back nonce is served: {served}"
    );
    let fourth = dispatch(&fixture, task_call(4, NONCE, Some("k6-b"), json!({}))).await;
    assert!(
        message(&fourth).contains(REPLAY),
        "the nonce was given back twice: {fourth}"
    );
}

/// The answer accepting `challenge`'s X14 question.
fn accept(challenge: &Value) -> Value {
    let state = challenge["result"]["requestState"].clone();
    let key = challenge["result"]["inputRequests"]
        .as_object()
        .and_then(|requests| requests.keys().next().cloned())
        .unwrap_or_default();
    json!({
        "requestState": state,
        "inputResponses": { key: { "action": "accept" } },
    })
}

/// K6-K: a destructive surfaced tool. X14 asks, then the redemption, which
/// no longer declares the tasks extension, consumes the grant at the route
/// stage and is refused by the task surface. The consume spent the nonce, so
/// the same nonce re-sent is a replay. Green on base. Mutant mK6-uncond: the
/// refusal gives the nonce back past the witness and the spent mark.
#[tokio::test]
async fn a_stdio_task_intent_refusal_after_a_consumed_grant_keeps_the_nonce() {
    const NONCE: &str = "s3d2-k6k-nonce-0001";
    let fixture = signed_listing(json!({"destructiveHint": true, "readOnlyHint": false})).await;
    let ledger = fixture.meta.continuation();
    let challenge = dispatch(&fixture, task_call(1, NONCE, Some("k6k-a"), json!({}))).await;
    assert!(
        challenge.pointer("/result/requestState").is_some(),
        "premise: X14 asked: {challenge}"
    );
    let before = ledger.ledger().len().await;
    let mut redemption = task_call(2, NONCE, Some("k6k-a"), accept(&challenge));
    let declared = &mut redemption["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"];
    declared.as_object_mut().expect("capabilities").remove("extensions");
    let refused = dispatch(&fixture, redemption).await;
    assert!(
        message(&refused).contains("extension to be declared"),
        "premise: the task surface's refusal: {refused}"
    );
    assert_eq!(
        ledger.ledger().len().await,
        before + 1,
        "premise: the redemption consumed the grant: {refused}"
    );
    let resent = dispatch(&fixture, task_call(3, NONCE, Some("k6k-b"), json!({}))).await;
    assert!(
        message(&resent).contains(REPLAY),
        "a nonce whose grant was consumed was given back: {resent}"
    );
    assert_eq!(fixture.rounds.load(Ordering::SeqCst), 0, "nothing was sent");
}

/// A plain (not task-augmented) signed `tools/call` of `name` under `nonce`.
fn plain_call(id: u64, name: &str, arguments: Value, nonce: &str) -> Value {
    let mut call = task_call(id, nonce, None, json!({}));
    let params = call["params"].as_object_mut().expect("params");
    params.remove("task");
    params.insert("name".into(), json!(name));
    params.insert("arguments".into(), arguments);
    call
}

/// K5 (stdio): the surfaced `echo` listed with a structurally invalid input
/// schema, `warm` or cold. Returns sends 1 and 2 of it under one nonce, then
/// a `gateway_search` under the same nonce twice, and the backend's
/// `tools/call` count.
async fn surfaced_invalid(warm: bool) -> ([Value; 4], usize) {
    const NONCE: &str = "s3d2-k5-nonce-0001";
    let served = backend_listing(json!([{"name": TOOL, "inputSchema": {"type": "string"}}])).await;
    let fixture = Box::pin(fixture_on_with(served, None, |config| {
        config.server.modern_protocol = true;
        config.security.posture = crate::security::SecurityPosture::Hardened;
        config.security.hardened.private_backends = vec![BACKEND.to_string()];
        let signing = &mut config.security.message_signing;
        signing.enabled = true;
        signing.shared_secret = "s3d2-stdio-k5-secret-0123456789abcdef".to_string();
        signing.require_nonce = true;
        signing.replay_window = 300;
        signing.key_id = "s3d2-k5".to_string();
        config.meta_mcp.surfaced_tools = vec![SurfacedToolConfig {
            server: BACKEND.to_string(),
            tool: TOOL.to_string(),
        }];
    }))
    .await;
    if warm {
        let backend = (fixture.meta.events_backend_registry().get(BACKEND))
            .expect("the backend is registered");
        backend.get_tools().await.expect("the backend lists");
    }
    let first = dispatch(&fixture, plain_call(1, TOOL, json!({}), NONCE)).await;
    let second = dispatch(&fixture, plain_call(2, TOOL, json!({}), NONCE)).await;
    let search = json!({"query": "echo"});
    let third = dispatch(&fixture, plain_call(3, "gateway_search", search.clone(), NONCE)).await;
    let fourth = dispatch(&fixture, plain_call(4, "gateway_search", search, NONCE)).await;
    let rounds = fixture.rounds.load(Ordering::SeqCst);
    ([first, second, third, fourth], rounds)
}

/// K5-R (stdio): a warm surfaced name withheld for its schema is answered as
/// a name that matches no tool, before anything acted; the nonce comes back
/// once.
#[tokio::test]
async fn a_withheld_surfaced_name_gives_the_nonce_back_on_stdio() {
    let ([first, second, third, fourth], rounds) = surfaced_invalid(true).await;
    assert_eq!(first["error"]["code"], -32601, "premise: absent: {first}");
    assert_eq!(second["error"]["code"], -32601, "the nonce was kept: {second}");
    assert!(third.get("error").is_none(), "send 3 was refused: {third}");
    assert!(message(&fourth).contains(REPLAY), "given back twice: {fourth}");
    assert_eq!(rounds, 0, "nothing was sent");
}

/// K5-K (stdio): the same name on a cold catalogue: the call lists the
/// backend first, so the nonce stays spent.
#[tokio::test]
async fn a_withheld_surfaced_name_after_a_cold_fill_keeps_the_nonce_on_stdio() {
    let ([first, second, ..], rounds) = surfaced_invalid(false).await;
    assert!(
        first["result"]["isError"] == true || first.get("error").is_some(),
        "premise: refused: {first}"
    );
    assert!(
        message(&second).contains(REPLAY),
        "the nonce was given back after a fill: {second} (first: {first})"
    );
    assert_eq!(rounds, 0, "nothing was sent");
}
