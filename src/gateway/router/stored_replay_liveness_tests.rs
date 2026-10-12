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
    let call = |key: &str| {
        json!({"name": TOOL, "arguments": {"folder": "inbox"}, "_meta": meta(Some(key), false)})
    };
    let first = send(&fx, "tools/call", TOOL, call("r4")).await;
    assert!(first.to_string().contains(MARKER), "premise: dispatched: {first}");
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.revoke_operator_grant().await;
    let again = send(&fx, "tools/call", TOOL, call("r4")).await;
    eprintln!("R4 answer: {again}");
    // Twin (i): a name that exists on no backend, on the same fixture.
    // Fresh key, same shape.
    let missing_name = "no_such_tool_8392";
    let missing_call = json!({
        "name": missing_name,
        "arguments": {"folder": "inbox"},
        "_meta": meta(Some("r4-missing"), false),
    });
    let truly_missing = send(&fx, "tools/call", missing_name, missing_call).await;
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

/// T7 (twin guard): a revoked vault plan-task repeat answers as a missing
/// name does. A task-augmented keyed `gateway_execute` completes; the grant
/// is revoked; the same task call repeated answers -32601 for the step tool,
/// equal, after normalising only each caller's own input (`id`, the step
/// tool it named), to the same keyed task-augmented call naming a step tool
/// that exists on no backend. Sends +0, and no stored output. M36 (a hint
/// beyond the echoed name) must fail this row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t7_revoked_vault_plan_repeat_answers_as_a_missing_name() {
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
        again.pointer("/error/code").and_then(Value::as_i64),
        Some(-32601),
        "T7: the revoked plan repeat is not -32601: {again}"
    );
    assert!(
        !again.to_string().contains(MARKER),
        "T7: stored output served: {again}"
    );
    assert!(
        again.pointer("/result/taskId").is_none(),
        "T7: a task was answered back: {again}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "T7: a step was re-run: {again}"
    );
    // The missing twin: the same keyed task-augmented call naming a step
    // tool that exists on no backend. Fresh key, same shape.
    let missing_tool = format!("{BACKEND}:no_such_tool_8392");
    let mut missing_params = json!({
        "name": "gateway_execute",
        "arguments": {"chain": [{"tool": missing_tool, "arguments": {"folder": "inbox"}}]},
        "_meta": meta(Some("t7-missing"), true),
    });
    missing_params["task"] = json!({});
    let fx_missing = fixture(false).await;
    let missing = send(&fx_missing, "tools/call", "gateway_execute", missing_params).await;
    eprintln!("T7 missing: {missing}");
    // Equal once only each caller's own input (the `id` and the step tool it
    // named) is normalised; any other detail still differs (M36).
    assert_eq!(
        caller_input_normalised(&again, TOOL),
        caller_input_normalised(&missing, "no_such_tool_8392"),
        "T7: the revoked answer differs from the missing-name answer: {again} vs {missing}"
    );
    assert!(
        fx_missing.gateway.tool_calls().is_empty(),
        "T7: the missing-name call reached the backend: {missing}"
    );
    // No never-granted twin here: an operator who never held the account has
    // no stored task under this key, so the same call is a FRESH task call
    // (answered "working", refused later inside the task), not a repeat. The
    // two are different operations, not a leak; R4 carries the strict twin.
}

/// A keyed task-augmented `gateway_invoke` that completed, for T8/T9.
async fn completed_task(fx: &Fx, key: &str) -> String {
    answer_marker(fx);
    let made = send(fx, "tools/call", "gateway_invoke", invoke_params(Some(key), true)).await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let done = wait_terminal(fx, &id).await;
    assert_eq!(
        done.pointer("/result/status").and_then(Value::as_str),
        Some("completed"),
        "premise: {done}"
    );
    id
}

/// T8 (E9): with custody failing (the account `Unavailable`), a repeated task
/// call answers exactly as the live call does (retryable), not as a missing
/// name: byte-identical after normalising only `id` to the same call made
/// live with a fresh key. M37 (the catalogue refusal kept first) must fail
/// this row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t8_unavailable_repeat_answers_as_the_live_call() {
    let fx = fixture(false).await;
    completed_task(&fx, "t8").await;
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.fail_custody_for_test(true);
    let again = send(&fx, "tools/call", "gateway_invoke", invoke_params(Some("t8"), true)).await;
    let live = send(&fx, "tools/call", "gateway_invoke", invoke_params(Some("t8-live"), false)).await;
    eprintln!("T8 repeat: {again}");
    eprintln!("T8 live: {live}");
    assert!(live.get("error").is_some(), "premise: the live call is refused: {live}");
    let (mut again_id, mut live_id) = (again.clone(), live.clone());
    again_id["id"] = Value::Null;
    live_id["id"] = Value::Null;
    assert_eq!(again_id, live_id, "T8: the repeat differs from the live call: {again} vs {live}");
    assert!(!again.to_string().contains(MARKER), "T8: stored output served: {again}");
    assert_eq!(fx.gateway.tool_calls().len(), sent, "T8: the call reached the backend: {again}");
}

/// T9 (E9 guard): the same outage, but the tool is ALSO withheld for a reason
/// that is not its account (its description is blocked). E9 must not fire:
/// the repeat answers exactly as the live call to that blocked tool does
/// (byte-identical after normalising only `id`), never the outage's retryable
/// answer. M37's leak variant (E9 applied to any withholding) must fail this
/// row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t9_unavailable_never_unhides_a_tool_hidden_for_another_reason() {
    let fx = fixture(false).await;
    completed_task(&fx, "t9").await;
    let sent = fx.gateway.tool_calls().len();
    fx.gateway
        .backends()
        .get(BACKEND)
        .expect("the backend")
        .block_tool_for_test(TOOL);
    fx.gateway.fail_custody_for_test(true);
    let again = send(&fx, "tools/call", "gateway_invoke", invoke_params(Some("t9"), true)).await;
    let live = send(&fx, "tools/call", "gateway_invoke", invoke_params(Some("t9-live"), false)).await;
    eprintln!("T9 repeat: {again}");
    eprintln!("T9 live: {live}");
    let (mut again_id, mut live_id) = (again.clone(), live.clone());
    again_id["id"] = Value::Null;
    live_id["id"] = Value::Null;
    assert_eq!(again_id, live_id, "T9: the blocked tool's repeat differs from its live call: {again} vs {live}");
    assert_ne!(
        again.pointer("/error/code").and_then(Value::as_i64),
        Some(-32603),
        "T9: the outage answer leaked for a tool withheld for another reason: {again}"
    );
    assert!(!again.to_string().contains(MARKER), "T9: stored output served: {again}");
    assert_eq!(fx.gateway.tool_calls().len(), sent, "T9: the call reached the backend: {again}");
}

/// S1 (guard; mutant M14): a LIVE vault account's keyed replay is served
/// the retained result at admission, with nothing sent and no more custody
/// resolutions than the base path (2). Deferring a proven-live replay to the
/// lift (M14) costs a third.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s1_live_account_replay_is_served_without_a_second_resolution() {
    let fx = fixture(false).await;
    answer_marker(&fx);
    let first = send(&fx, "tools/call", "gateway_invoke", invoke_params(Some("s1"), false)).await;
    assert!(first.to_string().contains(MARKER), "premise: dispatched: {first}");
    let (sent, resolved) = (fx.gateway.tool_calls().len(), fx.gateway.resolves());
    let again = send(&fx, "tools/call", "gateway_invoke", invoke_params(Some("s1"), false)).await;
    assert!(again.to_string().contains(MARKER), "S1: the live replay was not served: {again}");
    assert_eq!(fx.gateway.tool_calls().len(), sent, "S1: the replay was re-sent: {again}");
    // Measured on the release base without STORED.2 (573338311): the live
    // replay resolves custody twice (the route-stage verdict and the
    // dispatch's own read). STORED.2 may not add a third.
    assert!(
        fx.gateway.resolves() <= resolved + 2,
        "S1: the live replay resolved custody {} times (base: 2)",
        fx.gateway.resolves() - resolved
    );
}

/// S4 (mutant M16): a keyed single-call replay during a custody outage
/// (the account `Unavailable`) defers, its live resolution fails, and the
/// answer equals the same call made live (normalising only `id`); the
/// retained result is never served. Serving `Unavailable` at admission as if
/// it were live (M16) must fail this row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s4_outage_replay_answers_as_the_live_call() {
    let fx = fixture(false).await;
    answer_marker(&fx);
    let first = send(&fx, "tools/call", "gateway_invoke", invoke_params(Some("s4"), false)).await;
    assert!(first.to_string().contains(MARKER), "premise: dispatched: {first}");
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.fail_custody_for_test(true);
    let again = send(&fx, "tools/call", "gateway_invoke", invoke_params(Some("s4"), false)).await;
    let live = send(&fx, "tools/call", "gateway_invoke", invoke_params(Some("s4-live"), false)).await;
    eprintln!("S4 repeat: {again}");
    eprintln!("S4 live: {live}");
    assert!(live.get("error").is_some(), "premise: the live call is refused: {live}");
    assert!(!again.to_string().contains(MARKER), "S4: the retained result was served: {again}");
    let (mut again_id, mut live_id) = (again.clone(), live.clone());
    again_id["id"] = Value::Null;
    live_id["id"] = Value::Null;
    assert_eq!(again_id, live_id, "S4: the replay differs from the live call: {again} vs {live}");
    assert_eq!(fx.gateway.tool_calls().len(), sent, "S4: the call reached the backend: {again}");
}

/// L3 (mutant M3): two deferred replays in one memo scope, under different
/// keys. Each take consumes only its own entry, once; a key never recorded
/// takes nothing.
#[tokio::test]
async fn l3_a_deferred_replay_is_taken_only_by_its_own_key_once() {
    use crate::gateway::meta_mcp::visible::{
        DeferredReplay, deferred_replay_key, record_deferred_replay, take_deferred_replay,
        with_visibility_memo,
    };
    let retry = |key: &str| crate::protocol::mrtr::RetryFields {
        input_responses: None,
        request_state: None,
        idempotency_key: Some(key.to_string()),
        malformed: Vec::new(),
        attestation: None,
    };
    let entry = |text: &str| DeferredReplay {
        response: crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            json!({"content": [{"type": "text", "text": text}]}),
        ),
        audit: None,
        tool_name: "gateway_invoke".to_string(),
        arguments: json!({}),
    };
    with_visibility_memo(async {
        let a = deferred_replay_key(BACKEND, TOOL, &retry("l3-a")).expect("keyed");
        let b = deferred_replay_key(BACKEND, TOOL, &retry("l3-b")).expect("keyed");
        let never = deferred_replay_key(BACKEND, TOOL, &retry("l3-never")).expect("keyed");
        record_deferred_replay(a.clone(), entry("A"));
        record_deferred_replay(b.clone(), entry("B"));
        assert!(take_deferred_replay(&never).is_none(), "L3: an unrecorded key took an entry");
        let took_a = take_deferred_replay(&a).expect("L3: key a takes its entry");
        assert!(took_a.response.to_value_lossy().to_string().contains("\"A\""), "L3: key a took another entry");
        assert!(take_deferred_replay(&a).is_none(), "L3: key a took its entry twice");
        let took_b = take_deferred_replay(&b).expect("L3: key b keeps its entry");
        assert!(took_b.response.to_value_lossy().to_string().contains("\"B\""), "L3: key b took another entry");
    })
    .await;
}

/// O4 (mutant M24): with no outcome recorded (no open memo, or the pre-pass
/// never ran), a managed account's replay defers; it is served at admission
/// only once the request recorded the account `Live`.
#[tokio::test]
async fn o4_an_unfilled_outcome_defers_and_only_live_serves() {
    use crate::gateway::meta_mcp::visible::{
        AccountOutcome, record_account_outcome, with_visibility_memo,
    };
    let mut gateway = DirectAccountGateway::new(sole_operator(), &Binding::Connected);
    let meta = gateway.take_meta();
    let account = meta.target_account(BACKEND, TOOL).expect("premise: a managed account");
    assert!(meta.stored_replay_defers(BACKEND, TOOL), "O4: an unfilled outcome was served");
    let live = with_visibility_memo(async {
        let unfilled = meta.stored_replay_defers(BACKEND, TOOL);
        record_account_outcome(BACKEND, &account, AccountOutcome::Live);
        (unfilled, meta.stored_replay_defers(BACKEND, TOOL))
    })
    .await;
    assert!(live.0, "O4: an unfilled outcome inside a memo was served");
    assert!(!live.1, "O4 control: a Live outcome still defers");
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

/// R6u (E7 unit): a per-caller propagation backend without `account:`
/// classifies as needing proof at site 1, so its Replay defers. M34 (that
/// backend exempted like an unguarded one) makes the deferral false.
#[test]
fn r6u_per_caller_propagation_without_account_defers() {
    let mut gateway =
        DirectAccountGateway::new(sole_operator(), &Binding::Propagation);
    let meta = gateway.take_meta();
    // No `account:`, so no per-user account to judge ...
    assert!(
        meta.target_account(BACKEND, TOOL).is_none(),
        "R6u: a propagation backend without `account:` names an account"
    );
    // ... but it mints per caller, so site 1 defers to a live mint (E7).
    assert!(
        meta.mints_per_caller(BACKEND, TOOL),
        "R6u: a per-caller propagation backend mints nothing per caller"
    );
    assert!(
        meta.stored_replay_defers(BACKEND, TOOL),
        "R6u: a per-caller propagation backend's Replay does not defer"
    );
    // Contrast: a backend that mints nothing per caller is exempt.
    let empty = crate::gateway::meta_mcp::MetaMcp::new(Arc::new(
        crate::backend::BackendRegistry::new(),
    ));
    assert!(
        !empty.stored_replay_defers("no-backend", "no-tool"),
        "R6u: a backend that mints nothing per caller defers"
    );
}

/// R6m support: a token-exchange backend whose `IdP` is the key-server `IdP`
/// pattern from `token_exchange_live_tests`, with `kill()`.
mod r6m_token_exchange {
    use std::sync::Arc;

    use tower::ServiceExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::{Router, routing::get};
    use serde_json::{Value, json};
    use tokio::net::TcpListener;

    use crate::config::{
        KeyServerConfig, KeyServerPolicyConfig, KeyServerProviderConfig, PolicyMatchConfig,
        PolicyScopesConfig,
    };
    use crate::gateway::oauth::{GatewayKeyPair, jwks_handler};
    use crate::key_server::policy::PolicyEngine;
    use crate::key_server::{InMemoryTokenStore, KeyServer, OidcVerifier, handler::key_server_routes};

    const GATEWAY_ASSERTION_ISSUER: &str = "mcp-gateway";

    /// The in-process key-server `IdP`: `/auth/token` plus `/.well-known/jwks.json`.
    pub(super) struct LiveIdp {
        addr: std::net::SocketAddr,
        server: tokio::task::JoinHandle<()>,
    }

    impl LiveIdp {
        pub(super) async fn start(key: &Arc<GatewayKeyPair>) -> Self {
            let config = KeyServerConfig {
                enabled: true,
                oidc: vec![KeyServerProviderConfig {
                    issuer: GATEWAY_ASSERTION_ISSUER.to_string(),
                    jwks_uri: Some(String::new()),
                    discovery_url: None,
                    auto_discover: false,
                    audiences: Vec::new(),
                    allowed_domains: Vec::new(),
                }],
                policies: vec![KeyServerPolicyConfig {
                    match_criteria: PolicyMatchConfig {
                        domain: None,
                        issuer: GATEWAY_ASSERTION_ISSUER.to_string(),
                        email: None,
                        group: None,
                    },
                    scopes: PolicyScopesConfig {
                        backends: vec!["*".to_string()],
                        tools: vec!["*".to_string()],
                        rate_limit: 42,
                    },
                }],
                ..KeyServerConfig::default()
            };
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind an ephemeral port");
            let addr = listener.local_addr().expect("a local address");
            let mut config = config;
            config.oidc[0].jwks_uri = Some(format!("http://{addr}/.well-known/jwks.json"));
            let key_server = Arc::new(KeyServer {
                store: Arc::new(InMemoryTokenStore::new()),
                oidc: Arc::new(OidcVerifier::with_http_client(
                    config.oidc.clone(),
                    reqwest::Client::new(),
                )),
                policy: Arc::new(PolicyEngine::new(config.policies.clone())),
                config,
            });
            let jwks_router = Router::new()
                .route("/.well-known/jwks.json", get(jwks_handler))
                .with_state(Arc::clone(key));
            let app = key_server_routes(key_server).merge(jwks_router);
            let server = tokio::spawn(async move {
                axum::serve(listener, app)
                    .await
                    .expect("the in-process IdP serves");
            });
            Self { addr, server }
        }

        pub(super) fn endpoint(&self) -> String {
            format!("http://{}/auth/token", self.addr)
        }

        /// Kill the `IdP` outright: any later mint must fail without it.
        pub(super) fn kill(self) {
            self.server.abort();
        }
    }

    /// A counting backend transport: `tools/call` answers the marker;
    /// listings answer the one tool without counting.
    /// The token-exchange backend R6m calls: per-caller propagation, no
    /// `account:`.
    pub(super) const TX: &str = "tx";

    /// The verified caller the `IdP` mints for.
    pub(super) fn alice() -> crate::key_server::oidc::VerifiedIdentity {
        crate::key_server::oidc::VerifiedIdentity {
            subject: "alice-subject".to_string(),
            email: "alice@corp.example".to_string(),
            name: None,
            groups: vec!["eng".to_string()],
            issuer: "https://corp-idp.example".to_string(),
        }
    }

    /// The router over [`TX`]. Its counting transport serves `alice`'s
    /// per-user slot (the binding token exchange mints under), so a mint that
    /// succeeds reaches it. Returns the send counter and the directories to
    /// keep alive.
    pub(super) async fn gateway(
        key: &Arc<crate::gateway::oauth::GatewayKeyPair>,
        endpoint: String,
        alice: &crate::key_server::oidc::VerifiedIdentity,
    ) -> (axum::Router, Arc<AtomicUsize>, (tempfile::TempDir, tempfile::TempDir)) {
        use crate::config::{BackendConfig, TransportConfig};
        use crate::identity_propagation::{
            IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
            TokenExchangeStrategy,
        };
        const AUDIENCE: &str = "https://tx.internal";
        const SCOPE: &str = "backends:tx tools:read";
        let sends = Arc::new(AtomicUsize::new(0));
        let backend = Arc::new(crate::backend::Backend::new(
            TX,
            BackendConfig {
                transport: TransportConfig::Http {
                    http_url: "https://tx.internal/mcp".to_string(),
                    streamable_http: Some(true),
                    protocol_version: None,
                },
                identity_propagation: Some(IdentityPropagationConfig {
                    strategy: PropagationStrategyKind::TokenExchange,
                    audience: AUDIENCE.to_string(),
                    required: true,
                    session_mode: SessionMode::Stateless,
                    token_exchange_endpoint: Some(endpoint.clone()),
                    token_exchange_scope: Some(SCOPE.to_string()),
                }),
                ..BackendConfig::r2_off()
            },
            &crate::config::FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        ));
        let counting: Arc<dyn crate::transport::Transport> = Arc::new(Counting {
            sends: Arc::clone(&sends),
        });
        backend.set_transport_for_test(Arc::clone(&counting));
        // The per-user slot token exchange dispatches on, keyed as its
        // `exchange_cache_key` builds it: `cache_binding(subject, audience)`
        // widened by the length-prefixed endpoint and scope.
        let subject = alice.stable_actor_id();
        let binding = format!(
            "idp:{}:{}:{}:{}:{}:{}:{}:{}",
            subject.len(),
            subject,
            AUDIENCE.len(),
            AUDIENCE,
            endpoint.len(),
            endpoint,
            SCOPE.len(),
            SCOPE,
        );
        backend.set_pooled_transport_for_test(
            &crate::backend::PoolKey::PerUser { binding },
            counting,
        );
        let tool: crate::protocol::Tool = serde_json::from_value(json!({
            "name": super::TOOL,
            "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
        }))
        .expect("a tool");
        backend.store_shared_tools_for_test(vec![tool]);
        let registry = Arc::new(crate::backend::BackendRegistry::new());
        assert!(registry.register(backend), "the fixture backend registers");

        let mut meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&registry));
        meta.set_identity_propagation(Arc::new(TokenExchangeStrategy::with_http_client(
            Arc::clone(key),
            300,
            reqwest::Client::new(),
        )));
        let log_dir = tempfile::tempdir().expect("a log directory");
        let log = Arc::new(
            crate::security::TransparencyLogger::open(Arc::new(
                crate::security::transparency_log::TransparencyLogConfig {
                    enabled: true,
                    path: log_dir.path().join("audit.jsonl").to_string_lossy().into_owned(),
                    key_id: "r6m".to_string(),
                    ..crate::security::transparency_log::TransparencyLogConfig::default()
                },
            ))
            .expect("the transparency log opens"),
        );
        meta.enable_transparency_log(Arc::clone(&log));
        let auth = crate::config::AuthConfig::default();
        let (mut state, store) = super::super::tests::test_router_app_state_with_auth(&auth).await;
        let state_mut = Arc::get_mut(&mut state).expect("state is unique");
        state_mut.backends = registry;
        state_mut.meta_mcp = Arc::new(meta);
        state_mut.transparency_log = Some(log);
        (super::super::create_router(state), sends, (log_dir, store))
    }

    /// A `tools/call` as `alice`, whose verified identity rides the request.
    pub(super) async fn send_as(
        router: &axum::Router,
        alice: &crate::key_server::oidc::VerifiedIdentity,
        params: Value,
    ) -> Value {
        let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params});
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "tools/call")
            .header("mcp-name", "gateway_invoke")
            .body(axum::body::Body::from(body.to_string()))
            .expect("a request");
        request.extensions_mut().insert(alice.clone());
        let response = router.clone().oneshot(request).await.expect("an answer");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }

    pub(super) struct Counting {
        pub(super) sends: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl crate::transport::Transport for Counting {
        async fn request(
            &self,
            method: &str,
            _params: Option<Value>,
        ) -> crate::Result<crate::protocol::JsonRpcResponse> {
            use crate::protocol::{JsonRpcResponse, RequestId};
            if method == "tools/call" {
                self.sends.fetch_add(1, Ordering::SeqCst);
                return Ok(JsonRpcResponse::success(
                    RequestId::Number(1),
                    json!({"content": [{"type": "text", "text": super::MARKER}]}),
                ));
            }
            if method == "tools/list" {
                return Ok(JsonRpcResponse::success(
                    RequestId::Number(1),
                    json!({"tools": [{"name": super::TOOL, "inputSchema": {"type": "object"}}]}),
                ));
            }
            Ok(JsonRpcResponse::success(
                RequestId::Number(1),
                json!({}),
            ))
        }

        async fn request_with_headers(
            &self,
            method: &str,
            params: Option<Value>,
            _extra_headers: &[(String, String)],
            _identity_key: Option<&str>,
            _resend: crate::transport::ResendPermission,
        ) -> crate::Result<crate::protocol::JsonRpcResponse> {
            self.request(method, params).await
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
}

/// R6m (E7 meta level, through the REAL replay entry): a keyed call succeeds
/// via token exchange; the `IdP` is killed and the clock moved past the cached
/// token's TTL; the same keyed repeat is refused, with nothing sent and no
/// stored output. Current-thread: the forced clock is this thread's.
#[tokio::test]
async fn r6m_token_exchange_replay_after_idp_kill_and_ttl_is_refused() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) = r6m_token_exchange::gateway(&key, idp.endpoint(), &alice).await;
    let call = || {
        json!({"name": "gateway_invoke",
            "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
                "arguments": {"folder": "inbox"}},
            "_meta": meta(Some("r6m"), false)})
    };

    // A keyed call succeeds through token exchange, over the real HTTP route.
    let first = r6m_token_exchange::send_as(&router, &alice, call()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: the token-exchange call did not dispatch: {first}"
    );
    assert_eq!(sends.load(Ordering::SeqCst), 1, "premise: {first}");

    // The `IdP` dies and the cached token's TTL (one hour) passes; the
    // retained result (one day) is still present.
    idp.kill();
    let now = crate::clock::unix_secs().expect("a test host clock reads after 1970");
    let _clock = crate::clock::test_clock::at_secs(now + 7200);

    // The same keyed repeat, through the same route: admission replays it with
    // its target, the replay defers (E7), the live mint fails without the
    // `IdP`, and nothing stored goes out.
    let again = r6m_token_exchange::send_as(&router, &alice, call()).await;
    eprintln!("R6m answer: {again}");
    assert!(
        !again.to_string().contains(MARKER),
        "R6m: the stored output was served: {again}"
    );
    assert!(again.get("error").is_some(), "R6m: not a refusal: {again}");
    assert_eq!(sends.load(Ordering::SeqCst), 1, "R6m: the call reached the backend: {again}");
}

/// T12 (site 5, M38): a task-augmented keyed call to a token-exchange backend
/// (per-caller mint, no `account:`, so Unjudged and still visible) completes;
/// the `IdP` dies and the cached token's TTL passes; the same keyed task call
/// is repeated. E9 does not apply (not Unavailable) and the catalogue passes,
/// so site 5 proves the account by resolving, which fails: the repeat answers
/// exactly as the same call made live does (normalising only `id`), never with
/// the stored task. Bypassing site 5 (M38) must fail this row.
/// Current-thread: the forced clock is this thread's.
#[tokio::test]
async fn t12_token_exchange_task_repeat_after_idp_kill_answers_as_live() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) = r6m_token_exchange::gateway(&key, idp.endpoint(), &alice).await;
    let call = |key: &str, task: bool| {
        let mut params = json!({"name": "gateway_invoke",
            "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
                "arguments": {"folder": "inbox"}},
            "_meta": meta(Some(key), task)});
        if task {
            params["task"] = json!({});
        }
        params
    };
    let made = r6m_token_exchange::send_as(&router, &alice, call("t12", true)).await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if sends.load(Ordering::SeqCst) >= 1 {
            break;
        }
        assert!(std::time::Instant::now() < bound, "premise: the task dispatched: {made}");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let sent = sends.load(Ordering::SeqCst);
    idp.kill();
    let now = crate::clock::unix_secs().expect("a test host clock reads after 1970");
    let _clock = crate::clock::test_clock::at_secs(now + 7200);
    let again = r6m_token_exchange::send_as(&router, &alice, call("t12", true)).await;
    let live = r6m_token_exchange::send_as(&router, &alice, call("t12-live", false)).await;
    eprintln!("T12 repeat: {again}");
    eprintln!("T12 live: {live}");
    assert!(live.get("error").is_some(), "premise: the live call is refused: {live}");
    assert_ne!(
        again.pointer("/result/taskId").and_then(Value::as_str),
        Some(id.as_str()),
        "T12: the stored task was answered back after the IdP died: {again}"
    );
    let (mut again_id, mut live_id) = (again.clone(), live.clone());
    again_id["id"] = Value::Null;
    live_id["id"] = Value::Null;
    assert_eq!(again_id, live_id, "T12: the repeat differs from the live call: {again} vs {live}");
    assert_eq!(sends.load(Ordering::SeqCst), sent, "T12: the call reached the backend: {again}");
}

/// S2b (mutant M28): the token-exchange backend's keyed replay with the
/// `IdP` ALIVE. Admission replays it with its target, the replay defers (E7:
/// a per-caller mint), resolution succeeds, and the lift serves the retained
/// result: the stored bytes, nothing sent again. A lift that refuses or
/// re-dispatches after a successful resolution (M28) must fail this row.
#[tokio::test]
async fn s2b_token_exchange_replay_is_lifted_when_the_mint_succeeds() {
    use std::sync::atomic::Ordering;

    let key = Arc::new(crate::gateway::oauth::GatewayKeyPair::generate().expect("keygen"));
    let idp = r6m_token_exchange::LiveIdp::start(&key).await;
    let alice = r6m_token_exchange::alice();
    let (router, sends, _dirs) = r6m_token_exchange::gateway(&key, idp.endpoint(), &alice).await;
    let call = || {
        json!({"name": "gateway_invoke",
            "arguments": {"server": r6m_token_exchange::TX, "tool": TOOL,
                "arguments": {"folder": "inbox"}},
            "_meta": meta(Some("s2b"), false)})
    };
    let first = r6m_token_exchange::send_as(&router, &alice, call()).await;
    assert!(first.to_string().contains(MARKER), "premise: dispatched: {first}");
    assert_eq!(sends.load(Ordering::SeqCst), 1, "premise: {first}");
    let again = r6m_token_exchange::send_as(&router, &alice, call()).await;
    assert!(again.to_string().contains(MARKER), "S2b: the lifted replay was not served: {again}");
    assert_eq!(sends.load(Ordering::SeqCst), 1, "S2b: the replay was re-sent: {again}");
    drop(idp);
}
