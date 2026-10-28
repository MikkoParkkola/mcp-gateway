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
    /// The served task executor: its store's committed rows (MIK-8406).
    tasks: Arc<crate::gateway::task_service::TaskExecutor>,
    /// The served Meta-MCP: its plan executor entries (MIK-8406).
    meta: Arc<crate::gateway::meta_mcp::MetaMcp>,
    _store: crate::gateway::router::tests::FixtureDir,
    audit: Option<tempfile::TempDir>,
    /// Last: it owns the Meta-MCP's audit log, which must outlive every
    /// field above that holds the logger.
    gateway: DirectAccountGateway,
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
            ..Default::default()
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

/// The `idp_refuse` records in an audited fixture's transparency log.
fn idp_refusals(fx: &Fx) -> usize {
    let dir = fx.audit.as_ref().expect("an audited fixture");
    std::fs::read_to_string(dir.path().join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter(|line| line.contains("\"action\":\"idp_refuse\""))
        .count()
}

/// [`fixture`] with an identity-propagation transparency log, which the
/// direct route requires before it mints (G1).
async fn fixture_with(surfaced: bool, audited: bool) -> Fx {
    fixture_bound(surfaced, audited, &Binding::Connected).await
}

/// [`fixture_with`] for a chosen `binding`: `Unconnected` is the operator who
/// never held the account, the R4/T7 no-access twin.
async fn fixture_bound(surfaced: bool, audited: bool, binding: &Binding) -> Fx {
    let auth = sole_operator();
    let mut gateway = DirectAccountGateway::new(auth.clone(), binding);
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
                    path: dir
                        .path()
                        .join("audit.jsonl")
                        .to_string_lossy()
                        .into_owned(),
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
    let tasks = Arc::clone(&state.task_executor);
    let served = Arc::clone(&state.meta_mcp);
    Fx {
        router: super::create_router(state),
        gateway,
        tasks,
        meta: served,
        _store: store,
        audit,
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

async fn send_full(fx: &Fx, name: &str, params: Value) -> (axum::http::StatusCode, Value) {
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {KEY}"))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
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
    let asked = send(
        fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(None, false),
    )
    .await;
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

/// `answer` with only the caller's own input normalised: the JSON-RPC `id`,
/// and every whole-word occurrence of `sent` (the tool name this caller
/// asked for, which the answer echoes) replaced by a placeholder. Nothing
/// else changes, so any other name, hint or field still differs (R4, T7).
fn caller_input_normalised(answer: &Value, sent: &str) -> Value {
    fn walk(value: &mut Value, sent: &str) {
        match value {
            Value::String(text) => *text = replace_word(text, sent),
            Value::Array(items) => items.iter_mut().for_each(|item| walk(item, sent)),
            Value::Object(fields) => fields.values_mut().for_each(|field| walk(field, sent)),
            _ => {}
        }
    }
    fn is_word(c: char) -> bool {
        c.is_alphanumeric() || c == '_' || c == '-'
    }
    fn replace_word(text: &str, sent: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(at) = rest.find(sent) {
            let before = rest[..at].chars().next_back();
            let after = rest[at + sent.len()..].chars().next();
            out.push_str(&rest[..at]);
            if before.is_some_and(is_word) || after.is_some_and(is_word) {
                out.push_str(sent);
            } else {
                out.push_str("<REQUESTED>");
            }
            rest = &rest[at + sent.len()..];
        }
        out.push_str(rest);
        out
    }
    let mut normalised = answer.clone();
    normalised["id"] = Value::Null;
    walk(&mut normalised, sent);
    normalised
}

/// The normaliser itself: only the `id` and whole-word matches of the
/// requested name change; a longer word containing it does not.
#[test]
fn caller_input_normalised_touches_only_the_id_and_the_requested_name() {
    let answer = json!({"id": 7, "error": {"code": -32601,
        "message": "No tool: read (reader read_x)"}});
    assert_eq!(
        caller_input_normalised(&answer, "read"),
        json!({"id": null, "error": {"code": -32601,
            "message": "No tool: <REQUESTED> (reader read_x)"}})
    );
}

/// Refused, with no stored output and nothing sent since `sent`.
fn assert_refused_unsent(fx: &Fx, row: &str, answer: &Value, sent: usize) {
    assert!(
        !answer.to_string().contains(MARKER),
        "{row}: the stored output was served: {answer}"
    );
    assert!(
        answer.get("error").is_some(),
        "{row}: not a refusal: {answer}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "{row}: the call reached the backend: {answer}"
    );
}

/// R1 (P2, HTTP): a keyed `gateway_invoke` dispatches while connected; the
/// grant is revoked; the same call gets the account's answer, never the
/// retained result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r1_keyed_invoke_after_revocation_is_not_served_the_retained_result() {
    let fx = fixture(false).await;
    answer_marker(&fx);
    let first = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("r1"), false),
    )
    .await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.revoke_operator_grant().await;
    let again = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("r1"), false),
    )
    .await;
    assert_refused_unsent(&fx, "R1", &again, sent);
}

/// R3 (P3, HTTP): a keyed continuation retry naming an unsurfaced tool takes
/// admission's plan branch; after revocation the same retry is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r3_unsurfaced_continuation_retry_after_revocation_is_refused() {
    let fx = fixture(false).await;
    let retry = continuation_retry(&fx, "r3").await;
    let first = send(&fx, "tools/call", TOOL, retry.clone()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
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
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let sent = fx.gateway.tool_calls().len();
    let again = send(&fx, "tools/call", TOOL, retry).await;
    assert!(
        again.to_string().contains(MARKER),
        "P3c: not served: {again}"
    );
    assert_eq!(
        again["result"]["_trace_id"], first["result"]["_trace_id"],
        "P3c: not the retained result"
    );
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
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.revoke_operator_grant().await;
    let _clock = crate::clock::test_clock::at_secs(later());
    let again = send(&fx, "tools/call", TOOL, retry).await;
    eprintln!("R3b answer: {again}");
    assert_refused_unsent(&fx, "R3b", &again, sent);
    assert_eq!(
        again.pointer("/error/code"),
        Some(&json!(-32602)),
        "R3b: not the continuation's invalid-params error: {again}"
    );
    assert_eq!(
        again.pointer("/error/message"),
        Some(&json!("JSON-RPC error -32602: continuation rejected")),
        "R3b: not the continuation's message: {again}"
    );
}

/// R3c (E1, the accepted behaviour change): a LIVE account replaying with an
/// expired continuation gets the continuation's error too, not the retained
/// result (upgrading.d records it).
#[tokio::test]
async fn r3c_expired_continuation_while_live_answers_the_continuation_error() {
    let fx = fixture(false).await;
    let retry = continuation_retry(&fx, "r3c").await;
    let first = send(&fx, "tools/call", TOOL, retry.clone()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let sent = fx.gateway.tool_calls().len();
    let _clock = crate::clock::test_clock::at_secs(later());
    let again = send(&fx, "tools/call", TOOL, retry).await;
    eprintln!("R3c answer: {again}");
    assert_refused_unsent(&fx, "R3c", &again, sent);
    assert_eq!(
        again.pointer("/error/code"),
        Some(&json!(-32602)),
        "R3c: not the continuation's invalid-params error: {again}"
    );
    assert_eq!(
        again.pointer("/error/message"),
        Some(&json!("JSON-RPC error -32602: continuation rejected")),
        "R3c: not the continuation's message: {again}"
    );
}

/// Polls `tasks/get` (up to 10 s) until the task is terminal.
async fn wait_terminal(fx: &Fx, id: &str) -> Value {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let got = send(
            fx,
            "tasks/get",
            id,
            json!({"taskId": id, "_meta": meta(None, true)}),
        )
        .await;
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
    let made = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("r5"), true),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let done = wait_terminal(&fx, &id).await;
    assert_eq!(
        done.pointer("/result/status").and_then(Value::as_str),
        Some("completed"),
        "premise: {done}"
    );
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.revoke_operator_grant().await;
    let again = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        invoke_params(Some("r5"), true),
    )
    .await;
    eprintln!("R5 repeat: {again}");
    assert_ne!(
        again.pointer("/result/taskId").and_then(Value::as_str),
        Some(id.as_str()),
        "R5: the stored task was answered back after revocation: {again}"
    );
    assert!(
        !again.to_string().contains(MARKER),
        "R5: stored output served: {again}"
    );
    assert!(
        again.pointer("/result/taskId").is_none(),
        "R5: a new task was made: {again}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "R5: the call reached the backend: {again}"
    );
}

/// R4 (E8 twin): a keyed call by the SURFACED name dispatches while
/// connected; after revocation the repeat answers exactly as the same keyed
/// call to a name that does not exist: byte-identical after normalising only
/// `id`, with nothing sent and no stored output. Both twins must hold: (i) a
/// name that exists on no backend, and (ii) the same name where it is not
/// surfaced, compared after normalising only each caller's own input; and
/// (iii) the same name asked by an operator who never held the account,
/// byte-identical but for `id`. The withheld name is never served stored and
/// never leaks its key through a 409. M36 (a hint beyond the echoed name,
/// such as "withheld") must fail this row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_revoked_surfaced_name_is_not_served_the_retained_result() {
    // The withheld half: surfaced, dispatched, revoked, repeated.
    let fx = fixture(true).await;
    answer_marker(&fx);
    let call = |key: &str| json!({"name": TOOL, "arguments": {"folder": "inbox"}, "_meta": meta(Some(key), false)});
    let first = send(&fx, "tools/call", TOOL, call("r4")).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.revoke_operator_grant().await;
    let (again_status, again) = send_full(&fx, TOOL, call("r4")).await;
    eprintln!("R4 answer: {again}");
    // Twin (i): a name that exists on no backend, on the same fixture.
    // Fresh key, same shape.
    let missing_name = "no_such_tool_8392";
    let missing_call = json!({
        "name": missing_name,
        "arguments": {"folder": "inbox"},
        "_meta": meta(Some("r4-missing"), false),
    });
    let (missing_status, truly_missing) = send_full(&fx, missing_name, missing_call).await;
    eprintln!("R4 truly-missing: {truly_missing}");
    // Twin (ii): never surfaced, so the same name matches no tool.
    // Fresh key, same shape.
    let fx_absent = fixture(false).await;
    let missing = send(&fx_absent, "tools/call", TOOL, call("r4-absent")).await;
    eprintln!("R4 absent: {missing}");
    // Twins (i) and (ii): equal once only each caller's own input (the `id`
    // and the tool name it asked for) is normalised. Any other trace of a
    // name, or any hidden-tool detail, still differs (M36).
    assert_eq!(
        caller_input_normalised(&again, TOOL),
        caller_input_normalised(&truly_missing, missing_name),
        "R4: the withheld answer differs from the truly-missing answer: {again} vs {truly_missing}"
    );
    assert_eq!(
        caller_input_normalised(&again, TOOL),
        caller_input_normalised(&missing, TOOL),
        "R4: the withheld answer differs from the missing-name answer: {again} vs {missing}"
    );
    // Twin (iii), the strictest: the SAME name asked by a caller with no
    // access (the operator who never connected the account). Nothing but the
    // `id` may differ, so revoked and never-granted cannot be told apart.
    let fx_never = fixture_bound(true, false, &Binding::Unconnected).await;
    let never = send(&fx_never, "tools/call", TOOL, call("r4-never")).await;
    eprintln!("R4 never-granted: {never}");
    let (mut again_id, mut never_id) = (again.clone(), never.clone());
    again_id["id"] = Value::Null;
    never_id["id"] = Value::Null;
    assert_eq!(
        again_id, never_id,
        "R4: the revoked answer differs from the never-granted answer: {again} vs {never}"
    );
    assert!(
        fx_never.gateway.tool_calls().is_empty(),
        "R4: the never-granted call reached the backend: {never}"
    );
    assert_eq!(
        again_status, missing_status,
        "R4: the revoked repeat's HTTP status differs from a missing name's"
    );
    assert_refused_unsent(&fx, "R4", &again, sent);
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "R4: the truly-missing call reached the backend: {truly_missing}"
    );
    assert!(
        fx_absent.gateway.tool_calls().is_empty(),
        "R4: the missing-name call reached the backend: {missing}"
    );
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
    let mut gateway = DirectAccountGateway::with_second(
        auth.clone(),
        &Binding::Connected,
        Second::PersonalAccount,
    );
    let (mut state, _store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = gateway.backends();
    state_mut.meta_mcp = Arc::new(gateway.take_meta());
    for backend in [BACKEND, PERSONAL_BACKEND] {
        let tool: crate::protocol::Tool =
            serde_json::from_value(json!({"name": TOOL, "inputSchema": {"type": "object"}}))
                .expect("a tool");
        gateway
            .backends()
            .get(backend)
            .expect("registered")
            .store_shared_tools_for_test(vec![tool]);
    }
    let tasks = Arc::clone(&state.task_executor);
    let served = Arc::clone(&state.meta_mcp);
    let fx = Fx {
        router: super::create_router(state),
        gateway,
        tasks,
        meta: served,
        _store: Arc::new(tempfile::tempdir().unwrap()),
        audit: None,
    };
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
    assert!(
        refused.get("error").is_some(),
        "the revoked account still dispatched: {refused}"
    );
    assert_eq!(
        fx.gateway.tool_calls_to(BACKEND),
        1,
        "the revoked account reached its backend"
    );
    let live = send(&fx, "tools/call", "gateway_invoke", call(PERSONAL_BACKEND)).await;
    assert!(
        live.get("error").is_none(),
        "the other account was revoked too: {live}"
    );
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
    let gateway =
        DirectAccountGateway::with_second(sole_operator(), &Binding::Connected, Second::External);
    assert!(
        gateway.backends().get(BACKEND).is_some(),
        "BACKEND is registered"
    );
    assert!(
        gateway.backends().get(EXTERNAL_BACKEND).is_some(),
        "the external backend is registered"
    );
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
    let first = send(
        &fx,
        "tools/call",
        "gateway_execute",
        execute_params("s6", false),
    )
    .await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: the plan ran: {first}"
    );
    let sent = fx.gateway.tool_calls().len();
    let again = send(
        &fx,
        "tools/call",
        "gateway_execute",
        execute_params("s6", false),
    )
    .await;
    assert!(
        again.to_string().contains(MARKER),
        "S6: the retained plan was not served: {again}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "S6: a step was re-run: {again}"
    );
}

#[path = "stored_replay_liveness_plan_tests.rs"]
mod plan;
mod rebind;
#[path = "stored_replay_liveness_site5_tests.rs"]
mod site5;
#[path = "stored_replay_liveness_token_exchange_tests.rs"]
mod token_exchange;
