// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8406 bridged managed-account rows: a bridged caller's connected vault
//! account, revoked after a keyed plan ran. Its live call answers the
//! reconnect offer with data, so these rows carry the offer oracle.

use std::sync::atomic::Ordering;

use super::*;
use crate::personal_accounts::AccountKey;
use crate::personal_accounts::revoke_fixture::{Seed, grant};

/// The issuer [`config`]'s descriptor names, which the account key carries.
const DESCRIPTOR_ISSUER: &str = "https://issuer.fixture.test";

/// The bridged caller `alice`'s key on [`ACCOUNT`].
fn alice_key() -> AccountKey {
    AccountKey {
        principal_authority: "openwebui-adapter:20:fixture-installation".into(),
        principal_subject: "alice".into(),
        backend_id: ACCOUNT.into(),
        resource: RESOURCE.into(),
        oauth_issuer: DESCRIPTOR_ISSUER.into(),
    }
}

/// The gateway with `alice` connected on [`ACCOUNT`] at the descriptor's
/// own revision, so her dispatch mints and reaches her per-user slot.
async fn connected() -> Gateway {
    let config = config(std::path::Path::new("/unused"), Shape::Bridged);
    let descriptors = config
        .accounts
        .as_ref()
        .and_then(|a| a.descriptors.as_ref());
    let descriptor = &descriptors.expect("descriptors")[ACCOUNT];
    let mut seeded = grant("alice");
    seeded.descriptor_revision = crate::personal_accounts::descriptor_revision(descriptor)
        .expect("the descriptor has a revision");
    gateway_seeded(Shape::Bridged, &[(alice_key(), seeded, Seed::Connected)]).await
}

/// Revoke `alice`'s grant through the custody the dispatch reads.
async fn revoke(gw: &Gateway) {
    gw.fixture
        .handles()
        .revocation
        .invalidate(&alice_key())
        .await
        .expect("the seeded grant revokes");
}

/// A `tools/call` of `name` with `arguments`, keyed by `key` when given.
fn keyed(name: &str, arguments: &Value, key: Option<&str>) -> Value {
    let mut meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    if let Some(key) = key {
        meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    }
    call(
        "tools/call",
        &json!({"name": name, "arguments": arguments, "_meta": meta}),
    )
}

/// [`rpc`] at `/mcp` as the bridged `alice`, with the protocol header the
/// 2026-07-28 `_meta` needs.
async fn send(gw: &Gateway, body: &Value) -> Value {
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", format!("Bearer {API_KEY}"))
        .header("x-openwebui-assertion", assertion(HMAC, "alice"))
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", body["method"].as_str().unwrap_or_default())
        .header(
            "mcp-name",
            body["params"]["name"]
                .as_str()
                .or_else(|| body["params"]["taskId"].as_str())
                .unwrap_or_default(),
        )
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = gw.router.clone().oneshot(request).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).expect("a JSON-RPC body")
}

/// The single `gateway_execute` form: one `list_files` on [`BACKEND`].
fn single() -> Value {
    json!({"tool": format!("{BACKEND}:list_files"), "arguments": {}})
}

/// F0 (fixture check, not a MIK-8406 row): a connected bridged caller's
/// keyed `gateway_execute` mints, reaches her slot once and enters the plan
/// executor once; once revoked, her live call answers the reconnect offer
/// with data.
#[tokio::test]
async fn f0_a_seeded_bridged_caller_dispatches_then_is_offered_after_revoke() {
    let gw = Box::pin(connected()).await;
    let entered = crate::gateway::meta_mcp::plan_entries::count(&gw.meta);
    let first = send(&gw, &keyed("gateway_execute", &single(), Some("f0"))).await;
    assert!(
        first.to_string().contains(SLOT_MARKER),
        "the plan did not dispatch: {first}"
    );
    assert_eq!(gw.sends.load(Ordering::SeqCst), 1, "{first}");
    assert_eq!(
        crate::gateway::meta_mcp::plan_entries::count(&gw.meta) - entered,
        1,
        "the served Meta-MCP did not count the plan"
    );
    revoke(&gw).await;
    let live = send(&gw, &keyed("gateway_execute", &single(), None)).await;
    assert_eq!(live["error"]["code"], -32001, "{live}");
    assert_eq!(live["error"]["data"]["account_id"], ACCOUNT, "{live}");
    assert_eq!(
        live["error"]["data"]["error"]["code"], "reconnect_required",
        "{live}"
    );
    assert_eq!(gw.sends.load(Ordering::SeqCst), 1, "the live call sent");
}

/// A chain of two `list_files` reads on [`BACKEND`].
fn chain() -> Value {
    json!({"chain": [single(), single()]})
}

/// A `gateway_run_playbook` of `name` with no inputs.
fn playbook(name: &str) -> Value {
    json!({"name": name, "arguments": {}})
}

/// Register two playbooks of two `list_files` reads each: `reads_abort`
/// (`on_error: abort`) and `reads_continue` (`on_error: continue`).
fn register_playbooks(gw: &Gateway) {
    let mut engine = crate::playbook::PlaybookEngine::new();
    for (name, on_error) in [("reads_abort", "abort"), ("reads_continue", "continue")] {
        let step = |step: &str| json!({"name": step, "server": BACKEND, "tool": "list_files", "arguments": {}});
        let definition = serde_json::from_value(json!({"playbook": "1.0", "name": name,
            "description": "two reads", "steps": [step("s0"), step("s1")],
            "on_error": on_error}))
        .expect("the playbook deserialises");
        engine.register(definition);
    }
    gw.meta.set_playbook_engine(engine);
}

/// [`keyed`] as a task-augmented call.
fn tasked(name: &str, arguments: &Value, key: &str) -> Value {
    let mut body = keyed(name, arguments, Some(key));
    body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
        json!({"extensions": {"io.modelcontextprotocol/tasks": {}}});
    body["params"]["task"] = json!({});
    body
}

/// `answer` with the JSON-RPC `id` masked.
fn id_masked(answer: &Value) -> Value {
    let mut masked = answer.clone();
    masked["id"] = Value::Null;
    masked
}

/// Polls `tasks/get` (up to 10 s) until `id` completes.
async fn completed(gw: &Gateway, id: &str) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let meta = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":
                {"extensions": {"io.modelcontextprotocol/tasks": {}}},
        });
        let got = send(
            gw,
            &call("tasks/get", &json!({"taskId": id, "_meta": meta})),
        )
        .await;
        let status = got.pointer("/result/status").and_then(Value::as_str);
        if status == Some("completed") {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline
                && !matches!(status, Some("failed" | "cancelled")),
            "premise: the task completed: {got}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// What one revoked replay row measured.
struct Replayed {
    /// The keyed repeat's answer.
    again: Value,
    /// The live twin's answer: `twin` sent with a fresh key, not a task.
    live: Value,
    /// Slot sends the repeat added.
    sends: usize,
    /// Plan executor entries the repeat added.
    entries: usize,
    /// Committed task rows the repeat added.
    tasks: usize,
}

/// Run `(name, arguments)` keyed by `key` (as a task when `task`), with
/// every step dispatching; revoke `alice`; repeat it; then send the live
/// twin `twin`.
async fn replay_after_revoke(
    gw: &Gateway,
    (name, arguments): (&str, &Value),
    key: &str,
    task: bool,
    twin: (&str, &Value),
) -> Replayed {
    let body = if task {
        tasked(name, arguments, key)
    } else {
        keyed(name, arguments, Some(key))
    };
    // Every step of the form dispatches on the first run: one for a single
    // call, one per chain entry, two for the two-read playbooks.
    let steps = arguments["chain"]
        .as_array()
        .map_or(if name == "gateway_run_playbook" { 2 } else { 1 }, Vec::len);
    let first = send(gw, &body).await;
    if task {
        let id = first
            .pointer("/result/taskId")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("premise: a task was made: {first}"))
            .to_owned();
        completed(gw, &id).await;
    } else {
        assert!(
            first.to_string().contains(SLOT_MARKER) && first["result"]["isError"] != true,
            "premise: the plan completed: {first}"
        );
    }
    assert_eq!(
        gw.sends.load(Ordering::SeqCst),
        steps,
        "premise: every step reached the slot once"
    );
    revoke(gw).await;
    let (sent, entered, rows) = (
        gw.sends.load(Ordering::SeqCst),
        crate::gateway::meta_mcp::plan_entries::count(&gw.meta),
        gw.tasks.service.store.committed_count_for_test(),
    );
    let again = send(gw, &body).await;
    let (sends, entries, tasks) = (
        gw.sends.load(Ordering::SeqCst) - sent,
        crate::gateway::meta_mcp::plan_entries::count(&gw.meta) - entered,
        gw.tasks.service.store.committed_count_for_test() - rows,
    );
    let live = send(gw, &keyed(twin.0, twin.1, Some(&format!("{key}-live")))).await;
    assert_eq!(
        live["error"]["data"]["error"]["code"], "reconnect_required",
        "premise: the live twin answers the offer: {live}"
    );
    Replayed {
        again,
        live,
        sends,
        entries,
        tasks,
    }
}

/// The oracle every row shares: the repeat is the live twin's offer
/// (normalising only `id`, `error.data` kept), it serves no stored output,
/// makes no task, sends nothing and enters no plan executor.
fn assert_live_offer(row: &str, replayed: &Replayed) {
    let Replayed {
        again,
        live,
        sends,
        entries,
        tasks,
    } = replayed;
    assert!(
        !again.to_string().contains(SLOT_MARKER) && again.pointer("/result/taskId").is_none(),
        "{row}: the stored plan output was served: {again}"
    );
    assert_eq!(
        id_masked(again),
        id_masked(live),
        "{row}: the repeat is not the live twin's offer"
    );
    assert_eq!(*tasks, 0, "{row}: the repeat changed the task count");
    assert_eq!(*sends, 0, "{row}: the repeat reached the backend");
    // mProceed is killed only by this entries assert: a fall-through to the
    // live run refuses the same way and sends nothing. Keep it.
    assert_eq!(*entries, 0, "{row}: the repeat entered the plan executor");
}

/// P6b (sync, RED at 1577d7ff6): a keyed `gateway_execute` single, revoked
/// after it ran, answers the live twin's offer with data. Kills mSync and
/// mOfferLive.
#[tokio::test]
async fn p6b_sync_single_replay_answers_the_live_offer() {
    let gw = Box::pin(connected()).await;
    let one = single();
    let replayed = replay_after_revoke(
        &gw,
        ("gateway_execute", &one),
        "p6b",
        false,
        ("gateway_execute", &one),
    )
    .await;
    assert_live_offer("P6b", &replayed);
}

/// P6b-chain (sync, RED; CR-1): a keyed chain of two reads answers the first
/// unproven step's offer, which is the single form's live twin (no
/// byte-equality with the live chain, which re-sends step 0).
#[tokio::test]
async fn p6b_chain_sync_replay_answers_the_first_unproven_offer() {
    let gw = Box::pin(connected()).await;
    let replayed = replay_after_revoke(
        &gw,
        ("gateway_execute", &chain()),
        "p6b-chain",
        false,
        ("gateway_execute", &single()),
    )
    .await;
    assert_live_offer("P6b-chain", &replayed);
}

/// P6b-pb abort (sync, RED): an abort playbook's live twin is the bare offer
/// with data, and the replay must equal it.
#[tokio::test]
async fn p6b_pb_abort_sync_replay_answers_the_live_offer() {
    let gw = Box::pin(connected()).await;
    register_playbooks(&gw);
    let pb = playbook("reads_abort");
    let replayed = replay_after_revoke(
        &gw,
        ("gateway_run_playbook", &pb),
        "p6b-pba",
        false,
        ("gateway_run_playbook", &pb),
    )
    .await;
    assert_live_offer("P6b-pb abort", &replayed);
}

/// P6b-pb continue (sync, RED; CR-1): a continue playbook answers the first
/// unproven step's offer (the single form's live twin), not the live run's
/// success result.
#[tokio::test]
async fn p6b_pb_continue_sync_replay_answers_the_first_unproven_offer() {
    let gw = Box::pin(connected()).await;
    register_playbooks(&gw);
    let replayed = replay_after_revoke(
        &gw,
        ("gateway_run_playbook", &playbook("reads_continue")),
        "p6b-pbc",
        false,
        ("gateway_execute", &single()),
    )
    .await;
    assert_live_offer("P6b-pb continue", &replayed);
}

/// CR-2 (task half, lead ruling): a revoked vault target's task repeat
/// answers STORED.1's withheld frame, not the live offer, because
/// `refuse_stored_repeat` runs before the walk (call_dispatch.rs:478-482).
/// The frame is pinned, not compared with a live twin. Measured for this
/// bridged caller, no live call yields it: a fresh task call becomes a
/// working task; a plain call answers the offer on [`BACKEND`], -32001 "Tool
/// not found" on the capability server, and an `isError` result on an
/// account-free MCP backend. `refuse_stored_repeat` is its only producer,
/// and T7 (M36) proves the same frame equals a missing name for the sole
/// operator, so the pin is that rule, not an invention: the code, the
/// caller's own step tool and nothing else (no `data`, no account, offer or
/// hint). Also: no stored output, no task, nothing sent, no plan executor
/// entered.
fn assert_withheld_frame(row: &str, replayed: &Replayed) {
    let Replayed {
        again,
        sends,
        entries,
        tasks,
        ..
    } = replayed;
    assert!(
        !again.to_string().contains(SLOT_MARKER) && again.pointer("/result/taskId").is_none(),
        "{row}: the stored task or a new one was answered: {again}"
    );
    assert_eq!(
        id_masked(again),
        json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32601,
            "message": "JSON-RPC error -32601: Unknown tool: list_files"}}),
        "{row}: not STORED.1's withheld frame"
    );
    assert_eq!(*tasks, 0, "{row}: the repeat changed the task count");
    assert_eq!(*sends, 0, "{row}: the repeat reached the backend");
    assert_eq!(*entries, 0, "{row}: the repeat entered the plan executor");
}

/// P9l (ii) / P9o (task, GUARD under CR-2): a task-augmented keyed
/// `gateway_execute` single, revoked after it completed, answers STORED.1's
/// withheld frame; the live twin's offer is the premise CR-2 departs from.
#[tokio::test]
async fn p9l_task_single_repeat_answers_the_withheld_frame() {
    let gw = Box::pin(connected()).await;
    let one = single();
    let replayed = replay_after_revoke(
        &gw,
        ("gateway_execute", &one),
        "p9l",
        true,
        ("gateway_execute", &one),
    )
    .await;
    assert_withheld_frame("P9l (ii)", &replayed);
}

/// P9k (ii) (task, GUARD under CR-2): the same for a chain of two reads.
#[tokio::test]
async fn p9k_task_chain_repeat_answers_the_withheld_frame() {
    let gw = Box::pin(connected()).await;
    let replayed = replay_after_revoke(
        &gw,
        ("gateway_execute", &chain()),
        "p9k",
        true,
        ("gateway_execute", &single()),
    )
    .await;
    assert_withheld_frame("P9k (ii)", &replayed);
}

/// P9q abort (task, GUARD under CR-2): the same for an abort playbook.
#[tokio::test]
async fn p9q_task_abort_playbook_repeat_answers_the_withheld_frame() {
    let gw = Box::pin(connected()).await;
    register_playbooks(&gw);
    let pb = playbook("reads_abort");
    let replayed = replay_after_revoke(
        &gw,
        ("gateway_run_playbook", &pb),
        "p9qa",
        true,
        ("gateway_run_playbook", &pb),
    )
    .await;
    assert_withheld_frame("P9q abort", &replayed);
}

/// P9q continue (task, GUARD under CR-2): the same for a continue playbook.
#[tokio::test]
async fn p9q_task_continue_playbook_repeat_answers_the_withheld_frame() {
    let gw = Box::pin(connected()).await;
    register_playbooks(&gw);
    let replayed = replay_after_revoke(
        &gw,
        ("gateway_run_playbook", &playbook("reads_continue")),
        "p9qc",
        true,
        ("gateway_execute", &single()),
    )
    .await;
    assert_withheld_frame("P9q continue", &replayed);
}
