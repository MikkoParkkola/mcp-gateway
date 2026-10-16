// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392.STORED.1 batch B (test plan s1-t0..t2), on MIK-8356's per-user
//! backend: a stored task read judges the target against alpha's OWN
//! catalogue, and a cold slot is re-established with one resolution, never
//! one per poll. Driven through the public `/mcp` handler as alpha.

use std::sync::atomic::Ordering;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::slot_verdict_http_tests::{CLOSED, Gateway, gateway, gateway_tuned};
use crate::gateway::meta_mcp::slot_verdict_fixture::{
    BACKEND, BINDING, CallerSlot, Surfaced, TOOL, Warmth, serve_alpha_empty, valid,
};
use crate::key_server::oidc::VerifiedIdentity;

const OUTPUT: &str = "\"text\":\"ok\"";

/// A name no backend serves, swapped for [`TOOL`] in its answer.
const MISSING: &str = "no_such_tool_8392";

fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
    })
}

/// POST a modern request as alpha.
async fn send(gw: &Gateway, id: i64, method: &str, name: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method)
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request.extensions_mut().insert(VerifiedIdentity {
        subject: "alpha".to_string(),
        email: "alpha@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://issuer.example.invalid".to_string(),
    });
    let response = gw.router.clone().oneshot(request).await.expect("an answer");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn task_get(gw: &Gateway, id: &str) -> Value {
    send(
        gw,
        9,
        "tasks/get",
        id,
        json!({"taskId": id, "_meta": modern_meta()}),
    )
    .await
}

/// A finished task of alpha's own `read`, its output delivered once.
async fn finished(gw: &Gateway, key: &str) -> String {
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let made = send(
        gw,
        2,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"q": "x"}},
            "task": {}, "_meta": meta}),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let control = loop {
        let got = task_get(gw, &id).await;
        if got.to_string().contains(OUTPUT) || std::time::Instant::now() >= bound {
            break got;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    assert!(
        control.to_string().contains(OUTPUT),
        "control: while alpha's slot offers the tool the output is served: {control}"
    );
    id
}

/// Alpha's own slot relisted without the tool, complete.
fn alpha_lacks(gw: &Gateway) {
    let other: crate::protocol::Tool = serde_json::from_value(json!({
        "name": "other", "description": "Another.", "inputSchema": {"type": "object"}
    }))
    .expect("a tool");
    gw.meta
        .backends
        .get(BACKEND)
        .expect("the backend")
        .store_per_user_tools_for_test(BINDING, vec![other]);
}

fn backend(gw: &Gateway) -> std::sync::Arc<crate::backend::Backend> {
    gw.meta.backends.get(BACKEND).expect("the backend")
}

/// T8: alpha's own warm slot no longer lists the tool (the shared slot still
/// does): -32601. Red on base: the read is judged on policy only.
#[tokio::test]
async fn t8_alpha_s_own_slot_lacking_the_tool_answers_absent() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-t8").await;
    alpha_lacks(&gw);
    let read = task_get(&gw, &id).await;
    assert!(
        !read.to_string().contains(OUTPUT),
        "T8: output delivered: {read}"
    );
    // The gateway's own answer to a name that matches no tool, as alpha, with
    // that name swapped for TOOL (`read` is surfaced here, so it cannot be
    // the missing name itself).
    let twin = send(
        &gw,
        10,
        "tools/call",
        MISSING,
        json!({"name": MISSING, "arguments": {}, "_meta": modern_meta()}),
    )
    .await;
    let twin: Value = serde_json::from_str(
        &twin
            .get("error")
            .unwrap_or_else(|| panic!("premise: an absent name is refused: {twin}"))
            .to_string()
            .replace(MISSING, TOOL),
    )
    .expect("JSON");
    assert_eq!(
        read.get("error"),
        Some(&twin),
        "T8: a blocked stored read answers exactly as an absent name: {read}"
    );
}

/// T8t: the same, but alpha's slot is a TRUNCATED drain: it proves nothing
/// about the tool, so the output is served. Pinning; M7c turns it red.
#[tokio::test]
async fn t8t_a_truncated_slot_without_the_tool_still_delivers() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-t8t").await;
    alpha_lacks(&gw);
    backend(&gw).mark_per_user_truncated_for_test(BINDING);
    let read = task_get(&gw, &id).await;
    assert!(read.to_string().contains(OUTPUT), "T8t: {read}");
}

/// T6 (mutant M-cold; not an E4 row): a repeated task call whose catalogue
/// fill fails. Alpha's slot holds a stale, truncated list without the tool,
/// and alpha's upstream refuses the refetch, so alpha's view reads cold and
/// the stored-repeat judgement answers retryable before site 5: no stored
/// output, nothing sent. E4 itself (a carried failed fill at site 5) is
/// pinned by the seeded unit row `invoke::stored_proof::tests` T6u.
#[tokio::test]
async fn t6_a_repeat_whose_fill_failed_answers_retry_before_site_five() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let key = "s2-t6";
    let _ = finished(&gw, key).await;
    let upstream = crate::gateway::meta_mcp::slot_verdict_fixture::rearm_alpha_slot_with(
        &backend(&gw),
        &crate::gateway::meta_mcp::slot_verdict_fixture::valid(),
        true,
    );
    alpha_lacks(&gw);
    backend(&gw).mark_per_user_truncated_for_test(BINDING);
    backend(&gw).stale_per_user_tools_for_test(BINDING);
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let again = send(
        &gw,
        3,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"q": "x"}},
            "task": {}, "_meta": meta}),
    )
    .await;
    eprintln!("T6 answer: {again}");
    eprintln!("T6 lists {} calls {}", upstream.lists(), upstream.calls());
    assert!(
        upstream.lists() >= 1,
        "premise: the refetch was the fill: {again}"
    );
    assert!(
        !again.to_string().contains(OUTPUT),
        "T6: stored output served: {again}"
    );
    assert_eq!(upstream.calls(), 0, "T6: the call was sent: {again}");
    // The cold view answers first; site 5's E4 is the layer behind it.
    assert_eq!(
        again.pointer("/error/data/retryable"),
        Some(&serde_json::json!(true)),
        "T6: not the retryable answer: {again}"
    );
}

/// C1: alpha's slot is evicted after the task. The first read re-establishes
/// it with exactly one resolution and serves; N warm polls after it resolve
/// nothing. Red on base: no cold path, the read is judged on the shared view
/// with 0 resolutions.
#[tokio::test]
async fn c1_a_cold_read_resolves_once_then_warm_polls_resolve_nothing() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-c1").await;
    // Cold as the stored read sees it: alpha's index entry is gone. A real
    // eviction also drops the pooled slot, and the gateway reconnects it from
    // config; this fixture's per-user transport is scripted into the slot, so
    // the slot stays and only the index is forgotten.
    backend(&gw).forget_caller_slots_for_test();
    let before = gw.mints.load(Ordering::SeqCst);
    let first = task_get(&gw, &id).await;
    assert!(
        first.to_string().contains(OUTPUT),
        "C1: the cold read serves: {first}"
    );
    assert_eq!(
        gw.mints.load(Ordering::SeqCst) - before,
        1,
        "C1: the cold read re-establishes alpha's view with one resolution"
    );
    for _ in 0..5 {
        let _ = task_get(&gw, &id).await;
    }
    assert_eq!(
        gw.mints.load(Ordering::SeqCst) - before,
        1,
        "C1: warm polls after it resolve nothing"
    );
}

/// K1: touch-on-read. Alpha's slot is aged past the idle bound, a warm read
/// comes in, then the reaper runs: the slot survives because the read touched
/// it, and nothing was resolved. Red on base: no touch, the slot is evicted.
#[tokio::test]
async fn k1_a_warm_read_keeps_alpha_s_slot_from_idle_eviction() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-k1").await;
    backend(&gw).age_per_user_slot_for_test(BINDING, 301);
    let before = gw.mints.load(Ordering::SeqCst);
    let read = task_get(&gw, &id).await;
    assert!(read.to_string().contains(OUTPUT), "K1: served: {read}");
    backend(&gw).evict_idle_per_user_entries(std::time::Duration::from_secs(300));
    assert!(
        backend(&gw).holds_per_user_slot_for_test(BINDING),
        "K1: the read touched alpha's slot, so the reaper keeps it"
    );
    assert_eq!(gw.mints.load(Ordering::SeqCst), before, "K1: no resolution");
}

/// C1r (lead, 2026-10-12): C1 after a REAL eviction, which drops alpha's
/// pooled slot, its upstream connection and its index entry. The upstream is
/// re-attached as a gateway reconnects a per-user slot (`rearm`, as the
/// backend's own eviction rows do); the first stored read then claims the
/// cold view, resolves once, refills the slot and serves. Reconnecting from
/// config itself is not exercised by any fixture (stated in the PR).
#[tokio::test]
async fn c1r_a_read_after_a_real_eviction_resolves_once_and_serves() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-c1r").await;
    backend(&gw).age_per_user_slot_for_test(BINDING, 400);
    backend(&gw).evict_idle_per_user_entries(std::time::Duration::from_secs(300));
    assert!(
        !backend(&gw).holds_per_user_slot_for_test(BINDING),
        "premise: the real eviction dropped alpha's slot"
    );
    let upstream = crate::gateway::meta_mcp::slot_verdict_fixture::rearm_alpha_slot(&backend(&gw));
    let before = gw.mints.load(Ordering::SeqCst);
    let first = task_get(&gw, &id).await;
    assert!(
        first.to_string().contains(OUTPUT),
        "C1r: the cold read serves: {first}"
    );
    assert_eq!(
        gw.mints.load(Ordering::SeqCst) - before,
        1,
        "C1r: one resolution re-establishes alpha's view"
    );
    assert!(
        upstream.lists() >= 1,
        "C1r: the refill listed alpha's catalogue"
    );
    for _ in 0..5 {
        let _ = task_get(&gw, &id).await;
    }
    assert_eq!(
        gw.mints.load(Ordering::SeqCst) - before,
        1,
        "C1r: warm polls after the refill resolve nothing"
    );
}

/// A per-user backend with identity-propagation strategy Passthrough (as L7
/// configures it), warm and surfaced, offering TOOL on the shared slot.
async fn passthrough_gateway() -> Gateway {
    gateway_tuned(
        (CallerSlot::Valid, &valid(), Warmth::Warm),
        CLOSED,
        Surfaced::Yes,
        (
            |config: &mut crate::config::BackendConfig| {
                if let Some(idp) = config.identity_propagation.as_mut() {
                    idp.strategy =
                        crate::identity_propagation::PropagationStrategyKind::Passthrough;
                }
            },
            |_: &mut _| {},
        ),
        |_| {},
    )
    .await
}

/// P1 (MIK-8392 review): a Passthrough per-user backend is never indexed
/// (`remember_caller_slot` skips it, `listing_view` stays Cold), so before the
/// fix every stored read answered retryable and the output was never served.
/// The live path carries no per-caller binding for such a call, so its verdict
/// reads the shared slot; the stored read judges the shared catalogue too and
/// serves when it offers the tool.
#[tokio::test]
async fn p1_passthrough_stored_read_serves_from_the_shared_catalogue() {
    let gw = passthrough_gateway().await;
    let id = finished(&gw, "s1-p1").await;
    let read = task_get(&gw, &id).await;
    assert!(read.to_string().contains(OUTPUT), "P1: served: {read}");
    assert!(read.get("error").is_none(), "P1: no error: {read}");
}

/// P1b: the same, but the shared catalogue is complete without the tool:
/// -32601, never retryable.
#[tokio::test]
async fn p1b_passthrough_stored_read_answers_absent_when_the_shared_catalogue_lacks_it() {
    let gw = passthrough_gateway().await;
    let id = finished(&gw, "s1-p1b").await;
    let other =
        json!({"name": "other", "description": "Reads.", "inputSchema": {"type": "object"}});
    let _ = backend(&gw).remember_listed_tools(None, false, &[other]);
    let read = task_get(&gw, &id).await;
    assert_eq!(
        read.pointer("/error/code"),
        Some(&json!(-32601)),
        "P1b: {read}"
    );
    assert!(!read.to_string().contains(OUTPUT), "P1b: no output: {read}");
}

/// F3 (MIK-8392): alpha's pooled slot is evicted after its index entry is
/// kept — the listing view still names the caller while the pool lookup
/// finds a fresh entry, as a slot evicted between the two reads leaves it.
/// The sync judgement answers None (retryable), never served. Red without
/// the fix: the fresh entry reads as never-populated and the read is judged
/// on the other reasons only, serving a target alpha's own catalogue lacks.
#[tokio::test]
async fn f3_an_evicted_caller_slot_read_as_never_populated_is_retryable() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let _ = finished(&gw, "s1-f3").await;
    alpha_lacks(&gw);
    let _held = backend(&gw)
        .unpool_per_user_slot_for_test(BINDING)
        .expect("alpha's pooled slot");
    // The request's own identity, as `send` presents it.
    let alpha = VerifiedIdentity {
        subject: "alpha".to_string(),
        email: "alpha@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://issuer.example.invalid".to_string(),
    };
    assert!(
        backend(&gw)
            .caller_slot_held(&alpha.stable_actor_id())
            .is_some(),
        "premise: the index still names alpha's slot"
    );
    let caller = crate::gateway::meta_mcp::identified_caller(&alpha);
    assert!(
        gw.meta
            .stored_target_view(BACKEND, TOOL, caller.scope(), None)
            .is_none(),
        "F3: a caller slot gone from the pool is retryable, not served"
    );
}

/// F2 per-user (MIK-8392): a warm read ages alpha's catalogue past its TTL
/// and the upstream relists without the tool. The read refreshes through
/// the cold claim — first retryable or already refreshed — then answers
/// -32601. Control: a fresh catalogue serves with 0 resolutions. Red
/// without the fix: the stale list serves the withdrawn tool.
#[tokio::test]
async fn f2_a_stale_caller_catalogue_refreshes_past_its_ttl() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-f2").await;
    let before = gw.mints.load(Ordering::SeqCst);
    let control = task_get(&gw, &id).await;
    assert!(
        control.to_string().contains(OUTPUT),
        "control: served: {control}"
    );
    assert_eq!(
        gw.mints.load(Ordering::SeqCst) - before,
        0,
        "control: a fresh catalogue serves with 0 resolutions"
    );
    backend(&gw).age_tools_cache_for_test(Some(BINDING), 400);
    let _ = serve_alpha_empty(&gw.meta);
    let first = task_get(&gw, &id).await;
    assert!(
        first.pointer("/error/code") == Some(&json!(-32603))
            || first.pointer("/error/code") == Some(&json!(-32601)),
        "F2: first retryable or refreshed: {first}"
    );
    let second = task_get(&gw, &id).await;
    assert_eq!(
        second.pointer("/error/code"),
        Some(&json!(-32601)),
        "F2: then the withdrawn tool is absent: {second}"
    );
    assert!(
        !second.to_string().contains(OUTPUT),
        "F2: no output: {second}"
    );
}

/// F4 (MIK-8392): a cold view whose target is descriptor-blocked claims
/// nothing — 0 resolutions, no backend traffic — and the read answers the
/// existing -32601. Red without the fix: one resolution re-establishes a
/// view the read then refuses anyway.
#[tokio::test]
async fn f4_a_cold_descriptor_blocked_read_resolves_nothing() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-f4").await;
    backend(&gw).forget_caller_slots_for_test();
    backend(&gw).block_tool_for_test(TOOL);
    let before_mints = gw.mints.load(Ordering::SeqCst);
    let before_lists = gw.caller.lists();
    let read = task_get(&gw, &id).await;
    assert_eq!(
        read.pointer("/error/code"),
        Some(&json!(-32601)),
        "F4: the existing answer: {read}"
    );
    assert!(!read.to_string().contains(OUTPUT), "F4: no output: {read}");
    assert_eq!(
        gw.mints.load(Ordering::SeqCst),
        before_mints,
        "F4: 0 resolutions"
    );
    assert_eq!(gw.caller.lists(), before_lists, "F4: no backend traffic");
}

#[path = "stored_read_lease_tests.rs"]
mod lease;

/// F4 `admit_target` (MIK-8392): a cold view whose target is under the kill
/// switch claims nothing — 0 resolutions, no backend traffic — and the read
/// answers the policy refusal without the output. Red with
/// `refused_without_catalogue` ending in `false`: the read resolves a view
/// it then refuses anyway.
#[tokio::test]
async fn f4_a_cold_kill_switched_read_resolves_nothing() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-f4k").await;
    backend(&gw).forget_caller_slots_for_test();
    let cfg = crate::kill_switch::budget::CapabilityErrorBudgetConfig::default();
    for _ in 0..cfg.min_samples.max(cfg.window_size) {
        gw.meta
            .kill_switch()
            .record_capability_failure(BACKEND, TOOL, &cfg);
    }
    let before_mints = gw.mints.load(Ordering::SeqCst);
    let before_lists = gw.caller.lists();
    let read = task_get(&gw, &id).await;
    assert!(read.get("error").is_some(), "F4: refused: {read}");
    assert!(!read.to_string().contains(OUTPUT), "F4: no output: {read}");
    assert_eq!(
        gw.mints.load(Ordering::SeqCst),
        before_mints,
        "F4: 0 resolutions"
    );
    assert_eq!(gw.caller.lists(), before_lists, "F4: no backend traffic");
}

/// Passthrough past the TTL (MIK-8392 lead/gpt delta): a Passthrough
/// backend judges the shared catalogue, so a shared list past its TTL is
/// refreshed before the read judges it, and the read serves. Red with
/// Passthrough skipping the shared refresh: the stale list answers
/// retryable forever.
#[tokio::test]
async fn p1c_passthrough_stored_read_refreshes_a_stale_shared_catalogue() {
    let gw = passthrough_gateway().await;
    let id = finished(&gw, "s1-p1c").await;
    backend(&gw).age_tools_cache_for_test(None, 400);
    let lists = gw.shared.lists();
    let read = task_get(&gw, &id).await;
    assert!(read.to_string().contains(OUTPUT), "P1c: served: {read}");
    assert!(read.get("error").is_none(), "P1c: no error: {read}");
    assert!(gw.shared.lists() > lists, "P1c: the shared list refreshed");
}
