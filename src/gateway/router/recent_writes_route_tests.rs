// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Restart slice 8 route rows R1, R2, R3, R5, R13, S5: the writes each route counts.

use std::time::Instant;

use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx, fixture, post_meta_invoke, send};
use crate::gateway::meta_mcp::MetaMcp;
use crate::security::decision_record::Effect;

/// Every counted write since start: exact, so a delta never slides.
fn writes_total(meta: &MetaMcp) -> u64 {
    meta.recent_writes().sample(Instant::now()).writes_total
}

/// The fixture backend's `fx.calls`: every forward it answered but a listing.
fn dispatched(fx: &Fx) -> usize {
    fx.calls.load(std::sync::atomic::Ordering::SeqCst)
}

/// `read` on `backend`'s shared slot declares `effect`, asserted as the
/// dispatch reads it back.
fn declare(fx: &Fx, backend: &str, effect: Effect) {
    let mut tool = json!({"name": "read", "inputSchema": {
        "type": "object", "properties": {"cmd": {"type": "string"}}}});
    tool["annotations"] = json!({"readOnlyHint": effect == Effect::ReadOnly});
    let slot = fx.state.backends.get(backend).expect("fixture backend");
    slot.declare_slot_effects_for_test(None, vec![serde_json::from_value(tool).expect("a tool")]);
    assert_eq!(
        slot.declared_effect_for(None, "read"),
        Some(effect),
        "premise: {backend} declares {effect:?}"
    );
}

/// Send `method` to `uri` as `k-std`: the answer, the writes it added, and
/// the forwards the backend answered meanwhile.
async fn step(fx: &Fx, uri: &str, method: &str, params: Value) -> (Value, u64, usize) {
    let (total, calls) = (writes_total(&fx.state.meta_mcp), dispatched(fx));
    let (_, body) = send(fx, uri, "k-std", method, params, None).await;
    let added = writes_total(&fx.state.meta_mcp) - total;
    (body, added, dispatched(fx) - calls)
}

/// R1: `gateway_invoke` reaches the backend through hook 1: a may-write tool
/// adds one write, a read-only tool none. Read-only first, so the red run
/// checks both premises before the +1 fails. Kills hook 1 dropped and
/// `ReadOnly` counted.
#[tokio::test]
async fn r1_meta_invoke_counts_a_may_write_tool() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    for (effect, writes) in [(Effect::ReadOnly, 0), (Effect::MayWrite, 1)] {
        declare(&fx, "alpha", effect);
        let (total, calls) = (writes_total(&fx.state.meta_mcp), dispatched(&fx));
        let (status, body) =
            post_meta_invoke(&fx, "k-std", "alpha", "read", json!({}), None, None).await;
        assert!(
            status.is_success()
                && body.get("result").is_some()
                && body["result"]["isError"] != true,
            "premise: {effect:?} delivered: {status} {body}"
        );
        assert_eq!(dispatched(&fx), calls + 1, "premise: {effect:?} sent once");
        assert_eq!(
            writes_total(&fx.state.meta_mcp) - total,
            writes,
            "{effect:?}: writes added by one gateway_invoke"
        );
    }
}

/// R5's cases on `/mcp/{backend}`, each a premise (asserted) and the writes it
/// should add (collected in `failures`, so the red run reaches every premise).
async fn direct_cases(fx: &Fx, backend: &str, failures: &mut Vec<String>) {
    use super::backend_handlers::direct_permit_seams as seams;
    let uri = format!("/mcp/{backend}");
    let call = json!({"name": "read", "arguments": {}});
    let mut check = |case: &str, added: u64, want: u64| {
        if added != want {
            failures.push(format!("{backend} {case}: {added} writes, want {want}"));
        }
    };
    for (effect, want) in [(Effect::MayWrite, 1), (Effect::ReadOnly, 0)] {
        declare(fx, backend, effect);
        let (body, added, sent) = step(fx, &uri, "tools/call", call.clone()).await;
        assert!(
            sent == 1 && body.get("result").is_some() && body["result"]["isError"] != true,
            "premise: {backend} {effect:?} delivered once: {body}"
        );
        check(&format!("tools/call {effect:?}"), added, want);
    }
    let (body, added, _) = step(fx, &uri, "tools/list", json!({})).await;
    assert!(
        body["result"]["tools"].is_array(),
        "premise: {backend} tools/list answered: {body}"
    );
    check("tools/list", added, 0);
    let unlisted = json!({"ref": {"type": "ref/prompt", "name": "p"},
                          "argument": {"name": "a", "value": "b"}});
    let (body, added, sent) = step(fx, &uri, "completion/complete", unlisted).await;
    assert_eq!(
        sent, 1,
        "premise: {backend} forwarded completion/complete: {body}"
    );
    check("completion/complete", added, 1);
    // May-write again: a listing may have replaced the declaration, and a
    // refusal counted by mistake must show as +1.
    declare(fx, backend, Effect::MayWrite);
    seams::refuse_next_permit();
    let (body, added, sent) = step(fx, &uri, "tools/call", call).await;
    assert!(
        sent == 0 && body.to_string().contains(seams::REFUSED),
        "premise: {backend} permit refused before the send: {body}"
    );
    check("permit refusal", added, 0);
}

/// R5: hook 2 on both direct forwards, `alpha` (`forward_sanitized`) and
/// `alpha-pt` (`forward_plain`): a may-write `tools/call` +1, a read-only one
/// +0, `tools/list` +0, an unlisted method +1, a permit refusal +0. A redeemed
/// continuation +1 through `alpha` only: a retry on `alpha-pt` is rerouted to
/// the sanitized forward (`direct_dispatch.rs:622`). Kills hook 2 dropped on
/// either forward and the read list ignored.
#[tokio::test]
async fn r5_direct_tools_call_counts_on_both_forwards() {
    use super::direct_continuation_tests::{answers, call, state_of};
    let mut failures = Vec::new();
    for backend in ["alpha", "alpha-pt"] {
        let fx = fixture(Answer::Ok, |_| {}).await;
        direct_cases(&fx, backend, &mut failures).await;
    }
    // The listing declares no hint for `read`: undeclared, so counted.
    let fx = fixture(Answer::AskOnce, |_| {}).await;
    let total = writes_total(&fx.state.meta_mcp);
    let (_, asked) = call(&fx, "alpha", Some("alice"), json!({})).await;
    let retry = json!({"requestState": state_of(&asked), "inputResponses": answers()});
    let asked_writes = writes_total(&fx.state.meta_mcp) - total;
    let (_, done) = call(&fx, "alpha", Some("alice"), retry).await;
    assert!(done.get("error").is_none(), "premise: redeemed: {done}");
    assert_eq!(
        dispatched(&fx),
        2,
        "premise: the ask and the redeem were sent"
    );
    for (case, added) in [
        ("the asking call", asked_writes),
        (
            "the redeemed continuation",
            writes_total(&fx.state.meta_mcp) - total - asked_writes,
        ),
    ] {
        if added != 1 {
            failures.push(format!("alpha {case}: {added} writes, want 1"));
        }
    }
    assert!(failures.is_empty(), "R5 deltas: {failures:#?}");
}

/// R13: a backend health probe goes to the backend below every hook, so it
/// adds no write. Premise: the fake backend answered it. Its liveness method
/// is `ping` (`server/discover` on a modern peer), which `fx.calls` counts, so
/// an early `Ok` that sent nothing fails the premise.
#[tokio::test]
async fn r13_a_health_probe_counts_no_write() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let alpha = fx.state.backends.get("alpha").expect("fixture backend");
    let (total, calls) = (writes_total(&fx.state.meta_mcp), dispatched(&fx));
    let probed = alpha.health_probe(std::time::Duration::from_secs(5)).await;
    assert!(
        probed.is_ok() && dispatched(&fx) > calls,
        "premise: the fake backend answered the probe: {probed:?}"
    );
    assert_eq!(
        writes_total(&fx.state.meta_mcp) - total,
        0,
        "a health probe added a write"
    );
}

/// R2: a surfaced tool (`alpha`'s `read` under its own name on `/mcp`) is
/// sent through hook 1, so a may-write one adds a write.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn r2_a_surfaced_tool_counts_a_write() {
    let fx = super::direct_guards_fixture::fixture_built(
        Answer::Ok,
        super::route_matrix_driver_tests::surfacing,
    )
    .await;
    declare(&fx, "alpha", Effect::MayWrite);
    let params = json!({"name": "read", "arguments": {}});
    let (body, added, sent) = step(&fx, "/mcp", "tools/call", params).await;
    assert!(
        sent == 1 && body.get("result").is_some() && body["result"]["isError"] != true,
        "premise: the surfaced call was delivered once: {body}"
    );
    assert_eq!(added, 1, "writes added by one surfaced call");
}

/// The shared fixture with the admin key `k-admin` (`backends: ["*"]`, so an
/// unscoped admin): the web UI routes run only for an admin.
#[cfg(feature = "webui")]
async fn admin_fixture() -> Fx {
    use super::direct_guards_fixture::WITH_ADMIN;
    WITH_ADMIN.with(|s| s.set(true));
    let fx = fixture(Answer::Ok, |_| {}).await;
    WITH_ADMIN.with(|s| s.set(false));
    fx
}

/// `method` on the web UI route `uri` as `k-admin`, with `body` when given.
#[cfg(feature = "webui")]
async fn ui(fx: &Fx, method: &str, uri: &str, body: Option<Value>) -> (u16, Value) {
    use tower::ServiceExt;
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", "Bearer k-admin");
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let request = request
        .body(body.map_or_else(axum::body::Body::empty, |b| b.to_string().into()))
        .expect("request");
    let response = fx.router.clone().oneshot(request).await.expect("response");
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// R3: Try-a-tool on the web UI (`POST /ui/api/tools/call`) sends through
/// hook 1, so a confirmed may-write call adds a write.
#[cfg(feature = "webui")]
#[tokio::test]
async fn r3_ui_try_a_tool_counts_a_write() {
    let fx = Box::pin(admin_fixture()).await;
    declare(&fx, "alpha", Effect::MayWrite);
    let (total, calls) = (writes_total(&fx.state.meta_mcp), dispatched(&fx));
    let call = json!({"server": "alpha", "tool": "read", "arguments": {}, "confirm_write": true});
    let (status, body) = ui(&fx, "POST", "/ui/api/tools/call", Some(call)).await;
    assert!(
        status == 200 && dispatched(&fx) == calls + 1,
        "premise: the UI call was sent once: {status} {body}"
    );
    assert_eq!(
        writes_total(&fx.state.meta_mcp) - total,
        1,
        "writes added by one UI call"
    );
}

/// S5: end to end on one fixture: the admin restart GET reads the live
/// counter the hooks feed: `recent_writes.count` 0 before a may-write
/// `gateway_invoke`, 1 after it.
#[cfg(feature = "webui")]
#[tokio::test]
async fn s5_the_restart_get_reads_the_live_counter() {
    const RESTART: &str = "/ui/api/gateway/restart";
    let fx = Box::pin(admin_fixture()).await;
    let (status, before) = ui(&fx, "GET", RESTART, None).await;
    assert!(
        status == 200 && before["available"] == false,
        "premise: the admin GET answered: {status} {before}"
    );
    declare(&fx, "alpha", Effect::MayWrite);
    let (status, body) =
        post_meta_invoke(&fx, "k-std", "alpha", "read", json!({}), None, None).await;
    assert!(
        status.is_success() && body.get("result").is_some() && body["result"]["isError"] != true,
        "premise: the may-write call was delivered: {status} {body}"
    );
    let (_, after) = ui(&fx, "GET", RESTART, None).await;
    // Both counts last, so the red run reaches every premise first.
    assert_eq!(
        (
            &before["recent_writes"]["count"],
            &after["recent_writes"]["count"]
        ),
        (&json!(0), &json!(1)),
        "count before and after the call: {before} / {after}"
    );
}
