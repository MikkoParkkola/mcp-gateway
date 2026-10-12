// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.2: a stored single-call result is served only when the
//! caller's account is proven live in the request (design s2-d2/d3, test plan
//! s2-t0/t1). Rows R1, R3, R3b, R3c and R5 are red on the release line.

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::{ApiKeyConfig, AuthConfig, SurfacedToolConfig, api_key_digest_spec};
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, DirectAccountGateway,
};

const KEY: &str = "sole-operator-key";
const TOOL: &str = "read";
const MARKER: &str = "stored-output-8392";

struct Fx {
    router: axum::Router,
    gateway: DirectAccountGateway,
    _store: tempfile::TempDir,
    _audit: Option<tempfile::TempDir>,
}

fn sole_operator() -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(api_key_digest_spec(KEY.as_bytes())),
            expires_at: None,
            name: "operator".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: crate::config::ApiKeyKind::Shared,
        }],
        single_user: true,
        ..AuthConfig::default()
    }
}

/// The sole operator over the managed-account backend, connected. `surfaced`
/// surfaces [`TOOL`]; otherwise it is reachable through `gateway_invoke` and
/// through a continuation retry routed to its origin backend.
async fn fixture(surfaced: bool) -> Fx {
    fixture_with(surfaced, false).await
}

/// [`fixture`] with an identity-propagation transparency log, which the
/// direct route requires before it mints (G1).
async fn fixture_with(surfaced: bool, audited: bool) -> Fx {
    let auth = sole_operator();
    let mut gateway = DirectAccountGateway::new(auth.clone(), &Binding::Connected);
    let (mut state, store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = gateway.backends();
    let mut meta = gateway.take_meta();
    let audit = audited.then(|| tempfile::tempdir().expect("an audit dir"));
    if let Some(dir) = &audit {
        let log = Arc::new(
            crate::security::TransparencyLogger::open(Arc::new(
                crate::security::transparency_log::TransparencyLogConfig {
                    enabled: true,
                    path: dir.path().join("audit.jsonl").to_string_lossy().into_owned(),
                    key_id: "8392".to_string(),
                    ..crate::security::transparency_log::TransparencyLogConfig::default()
                },
            ))
            .expect("open log"),
        );
        meta.enable_transparency_log(Arc::clone(&log));
        state_mut.transparency_log = Some(log);
    }
    state_mut.meta_mcp = Arc::new(if surfaced {
        meta.with_surfaced_tools(vec![SurfacedToolConfig {
            server: BACKEND.to_string(),
            tool: TOOL.to_string(),
        }])
    } else {
        meta
    });
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": TOOL, "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
    }))
    .expect("a tool");
    gateway
        .backends()
        .get(BACKEND)
        .expect("the backend")
        .store_shared_tools_for_test(vec![tool]);
    Fx {
        router: super::create_router(state),
        gateway,
        _store: store,
        _audit: audit,
    }
}

fn meta(key: Option<&str>, tasks: bool) -> Value {
    let caps = if tasks {
        json!({"elicitation": {"form": {}}, "extensions": {"io.modelcontextprotocol/tasks": {}}})
    } else {
        json!({"elicitation": {"form": {}}})
    };
    let mut meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": caps,
    });
    if let Some(key) = key {
        meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    }
    meta
}

async fn send(fx: &Fx, method: &str, name: &str, params: Value) -> Value {
    send_to(fx, "/mcp", method, name, params).await
}

async fn send_to(fx: &Fx, uri: &str, method: &str, name: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {KEY}"))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method)
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn invoke_params(key: Option<&str>, tasks: bool) -> Value {
    let mut params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
        "_meta": meta(key, tasks),
    });
    if tasks {
        params["task"] = json!({});
    }
    params
}

fn answer_marker(fx: &Fx) {
    fx.gateway
        .answer_next(json!({"content": [{"type": "text", "text": MARKER}], "isError": false}));
}

fn ask(fx: &Fx) {
    fx.gateway.answer_next(json!({
        "resultType": "input_required",
        "inputRequests": {"k1": {"method": "elicitation/create",
            "params": {"message": "Which account?", "requestedSchema": {"type": "object"}}}},
        "requestState": "backend-state-1"
    }));
}

/// A keyed continuation retry naming the unsurfaced [`TOOL`], built from a
/// fresh interim round; the backend answers the retry with [`MARKER`].
async fn continuation_retry(fx: &Fx, key: &str) -> Value {
    ask(fx);
    answer_marker(fx);
    let asked = send(fx, "tools/call", "gateway_invoke", invoke_params(None, false)).await;
    let state = asked["result"]["requestState"]
        .as_str()
        .unwrap_or_else(|| panic!("premise: an interim answer with a state: {asked}"))
        .to_owned();
    json!({
        "name": TOOL,
        "arguments": {"folder": "inbox"},
        "requestState": state,
        "inputResponses": {"k1": {"action": "accept", "content": {"account": "work"}}},
        "_meta": meta(Some(key), false),
    })
}

/// Refused, with no stored output and nothing sent since `sent`.
fn assert_refused_unsent(fx: &Fx, row: &str, answer: &Value, sent: usize) {
    assert!(
        !answer.to_string().contains(MARKER),
        "{row}: the stored output was served: {answer}"
    );
    assert!(answer.get("error").is_some(), "{row}: not a refusal: {answer}");
    assert_eq!(fx.gateway.tool_calls().len(), sent, "{row}: the call reached the backend: {answer}");
}

/// R1 (P2, HTTP): a keyed `gateway_invoke` dispatches while connected; the
/// grant is revoked; the same call gets the account's answer, never the
/// retained result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r1_keyed_invoke_after_revocation_is_not_served_the_retained_result() {
    let fx = fixture(false).await;
    answer_marker(&fx);
    let first = send(&fx, "tools/call", "gateway_invoke", invoke_params(Some("r1"), false)).await;
    assert!(first.to_string().contains(MARKER), "premise: dispatched: {first}");
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.revoke_operator_grant().await;
    let again = send(&fx, "tools/call", "gateway_invoke", invoke_params(Some("r1"), false)).await;
    assert_refused_unsent(&fx, "R1", &again, sent);
}

/// R3 (P3, HTTP): a keyed continuation retry naming an unsurfaced tool takes
/// admission's plan branch; after revocation the same retry is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r3_unsurfaced_continuation_retry_after_revocation_is_refused() {
    let fx = fixture(false).await;
    let retry = continuation_retry(&fx, "r3").await;
    let first = send(&fx, "tools/call", TOOL, retry.clone()).await;
    assert!(first.to_string().contains(MARKER), "premise: dispatched: {first}");
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.revoke_operator_grant().await;
    let again = send(&fx, "tools/call", TOOL, retry).await;
    assert_refused_unsent(&fx, "R3", &again, sent);
}

/// P3c (control, green at base): the same retry with no revocation is served
/// the retained result with the original trace id, and nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p3c_unsurfaced_continuation_retry_while_live_is_served_the_retained_result() {
    let fx = fixture(false).await;
    let retry = continuation_retry(&fx, "p3c").await;
    let first = send(&fx, "tools/call", TOOL, retry.clone()).await;
    assert!(first.to_string().contains(MARKER), "premise: dispatched: {first}");
    let sent = fx.gateway.tool_calls().len();
    let again = send(&fx, "tools/call", TOOL, retry).await;
    assert!(again.to_string().contains(MARKER), "P3c: not served: {again}");
    assert_eq!(again["result"]["trace_id"], first["result"]["trace_id"], "P3c: not the retained result");
    assert_eq!(fx.gateway.tool_calls().len(), sent, "P3c: re-sent");
}

/// Seconds past now that put every continuation minted now past its lifetime
/// while a retained result (one day) is still present.
const PAST_CONTINUATION: u64 = 600;

fn later() -> u64 {
    crate::clock::unix_secs().expect("a test host clock reads after 1970") + PAST_CONTINUATION
}

/// R3b (E1): the continuation expires while the retained result is present;
/// after revocation the repeat answers the continuation's error, never the
/// retained result. Current-thread: the forced clock is this thread's.
#[tokio::test]
async fn r3b_expired_continuation_after_revocation_is_never_served_stored() {
    let fx = fixture(false).await;
    let retry = continuation_retry(&fx, "r3b").await;
    let first = send(&fx, "tools/call", TOOL, retry.clone()).await;
    assert!(first.to_string().contains(MARKER), "premise: dispatched: {first}");
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.revoke_operator_grant().await;
    let _clock = crate::clock::test_clock::at_secs(later());
    let again = send(&fx, "tools/call", TOOL, retry).await;
    assert_refused_unsent(&fx, "R3b", &again, sent);
}

/// R3c (E1, the accepted behaviour change): a LIVE account replaying with an
/// expired continuation gets the continuation's error too, not the retained
/// result (upgrading.d records it).
#[tokio::test]
async fn r3c_expired_continuation_while_live_answers_the_continuation_error() {
    let fx = fixture(false).await;
    let retry = continuation_retry(&fx, "r3c").await;
    let first = send(&fx, "tools/call", TOOL, retry.clone()).await;
    assert!(first.to_string().contains(MARKER), "premise: dispatched: {first}");
    let sent = fx.gateway.tool_calls().len();
    let _clock = crate::clock::test_clock::at_secs(later());
    let again = send(&fx, "tools/call", TOOL, retry).await;
    assert_refused_unsent(&fx, "R3c", &again, sent);
}

/// Polls `tasks/get` (up to 10 s) until the task is terminal.
async fn wait_terminal(fx: &Fx, id: &str) -> Value {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let got = send(fx, "tasks/get", id, json!({"taskId": id, "_meta": meta(None, true)})).await;
        let status = got.pointer("/result/status").and_then(Value::as_str);
        if matches!(status, Some("completed" | "failed" | "cancelled"))
            || tokio::time::Instant::now() >= deadline
        {
            return got;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// R5 (site 5): a keyed task-augmented `gateway_invoke` completes; the grant
/// is revoked; the same task call repeated is answered by the account, not by
/// the stored task's output, and makes no new task.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r5_repeated_task_call_after_revocation_is_not_served_the_stored_task() {
    let fx = fixture(false).await;
    answer_marker(&fx);
    let made = send(&fx, "tools/call", "gateway_invoke", invoke_params(Some("r5"), true)).await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let done = wait_terminal(&fx, &id).await;
    assert_eq!(done.pointer("/result/status").and_then(Value::as_str), Some("completed"), "premise: {done}");
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.revoke_operator_grant().await;
    let again = send(&fx, "tools/call", "gateway_invoke", invoke_params(Some("r5"), true)).await;
    eprintln!("R5 repeat: {again}");
    assert_ne!(
        again.pointer("/result/taskId").and_then(Value::as_str),
        Some(id.as_str()),
        "R5: the stored task was answered back after revocation: {again}"
    );
    assert!(!again.to_string().contains(MARKER), "R5: stored output served: {again}");
    assert!(again.pointer("/result/taskId").is_none(), "R5: a new task was made: {again}");
    assert_eq!(fx.gateway.tool_calls().len(), sent, "R5: the call reached the backend: {again}");
}

/// R4: a keyed call by the SURFACED name dispatches while connected; after
/// revocation the repeat must be refused with nothing sent. RED on the release
/// line (ef0e22e72): the retained result is served. With MIK-8356's withheld
/// name it is refused at the route stage, so this row then guards that answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_revoked_surfaced_name_is_not_served_the_retained_result() {
    let fx = fixture(true).await;
    answer_marker(&fx);
    let call = || {
        json!({"name": TOOL, "arguments": {"folder": "inbox"}, "_meta": meta(Some("r4"), false)})
    };
    let first = send(&fx, "tools/call", TOOL, call()).await;
    assert!(first.to_string().contains(MARKER), "premise: dispatched: {first}");
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.revoke_operator_grant().await;
    let again = send(&fx, "tools/call", TOOL, call()).await;
    eprintln!("R4 answer: {again}");
    assert_refused_unsent(&fx, "R4", &again, sent);
}

/// The two-account fixture MIK-8406 builds on: both managed accounts start
/// live; revoking one leaves the other dispatching, and calls are counted per
/// backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_account_fixture_revokes_one_account_only() {
    use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
        PERSONAL_BACKEND, Second,
    };
    let auth = sole_operator();
    let mut gateway =
        DirectAccountGateway::with_second(auth.clone(), &Binding::Connected, Second::PersonalAccount);
    let (mut state, _store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = gateway.backends();
    state_mut.meta_mcp = Arc::new(gateway.take_meta());
    for backend in [BACKEND, PERSONAL_BACKEND] {
        let tool: crate::protocol::Tool =
            serde_json::from_value(json!({"name": TOOL, "inputSchema": {"type": "object"}}))
                .expect("a tool");
        gateway.backends().get(backend).expect("registered").store_shared_tools_for_test(vec![tool]);
    }
    let fx = Fx { router: super::create_router(state), gateway, _store: tempfile::tempdir().unwrap(), _audit: None };
    let call = |backend: &str| {
        json!({"name": "gateway_invoke",
            "arguments": {"server": backend, "tool": TOOL, "arguments": {}},
            "_meta": meta(None, false)})
    };
    for backend in [BACKEND, PERSONAL_BACKEND] {
        let answer = send(&fx, "tools/call", "gateway_invoke", call(backend)).await;
        assert!(answer.get("error").is_none(), "{backend} live: {answer}");
        assert_eq!(fx.gateway.tool_calls_to(backend), 1, "{backend}: {answer}");
    }
    fx.gateway.revoke_operator_grant_on(BACKEND).await;
    let refused = send(&fx, "tools/call", "gateway_invoke", call(BACKEND)).await;
    assert!(refused.get("error").is_some(), "the revoked account still dispatched: {refused}");
    assert_eq!(fx.gateway.tool_calls_to(BACKEND), 1, "the revoked account reached its backend");
    let live = send(&fx, "tools/call", "gateway_invoke", call(PERSONAL_BACKEND)).await;
    assert!(live.get("error").is_none(), "the other account was revoked too: {live}");
    assert_eq!(fx.gateway.tool_calls_to(PERSONAL_BACKEND), 2, "{live}");
}

/// The external second backend MIK-8406's P6 uses: registered beside BACKEND,
/// with no managed account of its own, so revoking BACKEND's account is the
/// only grant the fixture holds.
#[test]
fn two_backend_fixture_registers_the_external_backend() {
    use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
        EXTERNAL_BACKEND, Second,
    };
    let gateway = DirectAccountGateway::with_second(sole_operator(), &Binding::Connected, Second::External);
    assert!(gateway.backends().get(BACKEND).is_some(), "BACKEND is registered");
    assert!(gateway.backends().get(EXTERNAL_BACKEND).is_some(), "the external backend is registered");
    assert_eq!(gateway.tool_calls_to(EXTERNAL_BACKEND), 0);
}

fn execute_params(key: &str, tasks: bool) -> Value {
    let mut params = json!({
        "name": "gateway_execute",
        "arguments": {"chain": [{"tool": format!("{BACKEND}:{TOOL}"), "arguments": {"folder": "inbox"}}]},
        "_meta": meta(Some(key), tasks),
    });
    if tasks {
        params["task"] = json!({});
    }
    params
}

/// S6 (guard; mutant M5): a keyed `gateway_execute` is retained; the same
/// call again, while live, is served the retained result with no step re-run.
/// Plans are not STORED.2's: a Replay with no target is served as today.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s6_retained_gateway_execute_is_served_not_rerun() {
    let fx = fixture(false).await;
    answer_marker(&fx);
    let first = send(&fx, "tools/call", "gateway_execute", execute_params("s6", false)).await;
    assert!(first.to_string().contains(MARKER), "premise: the plan ran: {first}");
    let sent = fx.gateway.tool_calls().len();
    let again = send(&fx, "tools/call", "gateway_execute", execute_params("s6", false)).await;
    assert!(again.to_string().contains(MARKER), "S6: the retained plan was not served: {again}");
    assert_eq!(fx.gateway.tool_calls().len(), sent, "S6: a step was re-run: {again}");
}

/// Expected gap, MIK-8406: a revoked plan replay is served as today; MIK-8406
/// flips this to a refusal. A task-augmented keyed `gateway_execute`
/// completes; the grant is revoked; the same task call repeated is answered
/// with the stored task. STORED.2 lists this as an OPEN gap, never as covered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plan_replay_after_revoke_is_mik_8406_gap() {
    let fx = fixture(false).await;
    answer_marker(&fx);
    let made = send(&fx, "tools/call", "gateway_execute", execute_params("t7", true)).await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let done = wait_terminal(&fx, &id).await;
    assert_eq!(done.pointer("/result/status").and_then(Value::as_str), Some("completed"), "premise: {done}");
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.revoke_operator_grant().await;
    let again = send(&fx, "tools/call", "gateway_execute", execute_params("t7", true)).await;
    eprintln!("T7 repeat: {again}");
    assert_eq!(
        again.pointer("/result/taskId").and_then(Value::as_str),
        Some(id.as_str()),
        "T7 gap moved: the revoked plan repeat is no longer answered with the stored task \
         (MIK-8406 inverts this row): {again}"
    );
    assert_eq!(fx.gateway.tool_calls().len(), sent, "T7: a step was re-run: {again}");
}

/// G1 (guard; mutant M31): on the direct route a revoked grant's keyed replay
/// is refused at stage 5 (the identity mint), before 7a/7b can serve a stored
/// answer; nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g1_direct_route_refuses_a_revoked_keyed_replay_at_stage_five() {
    let fx = fixture_with(false, true).await;
    answer_marker(&fx);
    let uri = format!("/mcp/{BACKEND}");
    let call = || {
        json!({"name": TOOL, "arguments": {"folder": "inbox"}, "_meta": meta(Some("g1"), false)})
    };
    let first = send_to(&fx, &uri, "tools/call", TOOL, call()).await;
    assert!(first.to_string().contains(MARKER), "premise: dispatched: {first}");
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.revoke_operator_grant().await;
    let again = send_to(&fx, &uri, "tools/call", TOOL, call()).await;
    eprintln!("G1 answer: {again}");
    assert_refused_unsent(&fx, "G1", &again, sent);
}

/// U1/U2: `alpha` binds no per-user account (not isolation-guarded), so no
/// liveness proof applies and stored answers are served as today.
mod unguarded {
    use std::sync::atomic::Ordering;

    use serde_json::{Value, json};

    use super::super::direct_guards_fixture::{Answer, Fx, fixture, send_with_headers};
    use super::{MARKER, meta};

    async fn call(fx: &Fx, params: Value) -> Value {
        let name = params["name"].as_str().unwrap_or_default().to_owned();
        let headers = [
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/call"),
            ("mcp-name", name.as_str()),
        ];
        send_with_headers(fx, "/mcp", "k-std", "tools/call", params, None, &headers)
            .await
            .1
    }

    fn invoke(key: &str, tasks: bool) -> Value {
        let mut params = json!({"name": "gateway_invoke",
            "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
            "_meta": meta(Some(key), tasks)});
        if tasks {
            params["task"] = json!({});
        }
        params
    }

    /// U1 (guard; mutant M32): a keyed replay on an unguarded backend is
    /// served the retained result; nothing is sent again.
    #[tokio::test]
    async fn u1_unguarded_keyed_replay_is_served() {
        let fx = fixture(Answer::Text(MARKER), |_| {}).await;
        let first = call(&fx, invoke("u1", false)).await;
        assert!(first.to_string().contains(MARKER), "premise: dispatched: {first}");
        let sent = fx.calls.load(Ordering::SeqCst);
        let again = call(&fx, invoke("u1", false)).await;
        assert!(again.to_string().contains(MARKER), "U1: not served: {again}");
        assert_eq!(fx.calls.load(Ordering::SeqCst), sent, "U1: re-sent: {again}");
    }

    /// U2 (guard; mutant M33): a repeated task call on an unguarded backend
    /// is answered with the stored task; nothing is sent again.
    #[tokio::test]
    async fn u2_unguarded_repeated_task_call_is_answered_with_the_stored_task() {
        let fx = fixture(Answer::Text(MARKER), |_| {}).await;
        let made = call(&fx, invoke("u2", true)).await;
        let id = made
            .pointer("/result/taskId")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
            .to_owned();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while fx.calls.load(Ordering::SeqCst) == 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let sent = fx.calls.load(Ordering::SeqCst);
        assert_eq!(sent, 1, "premise: the task dispatched once");
        let again = call(&fx, invoke("u2", true)).await;
        assert_eq!(
            again.pointer("/result/taskId").and_then(Value::as_str),
            Some(id.as_str()),
            "U2: not answered with the stored task: {again}"
        );
        assert_eq!(fx.calls.load(Ordering::SeqCst), sent, "U2: re-sent: {again}");
    }
}

/// The fixture's scripted backend failure (MIK-8406 P8i): with the account
/// live, the next call reaches the backend and fails; the one after succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixture_fail_next_fails_one_call_with_the_account_live() {
    let fx = fixture(false).await;
    fx.gateway.fail_next(503);
    let failed = send(&fx, "tools/call", "gateway_invoke", invoke_params(None, false)).await;
    assert!(failed.get("error").is_some() || failed.pointer("/result/isError") == Some(&json!(true)),
        "the scripted failure did not surface: {failed}");
    assert_eq!(fx.gateway.tool_calls().len(), 1, "the failing call reached the backend: {failed}");
    answer_marker(&fx);
    let ok = send(&fx, "tools/call", "gateway_invoke", invoke_params(None, false)).await;
    assert!(ok.to_string().contains(MARKER), "the next call succeeds: {ok}");
}

// Scratch only (MIK-8406 gap proof): never part of a PR.
#[path = "plan_repeat_unavailable_gap_tests.rs"]
mod plan_repeat_unavailable_gap_tests;
