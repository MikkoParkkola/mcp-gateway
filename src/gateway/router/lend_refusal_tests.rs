// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A required per-user backend whose credential mint answers with no header:
//! the slot lender refuses the call, which carried no credential of its own,
//! before anything is sent, and the delivered 403 records `refused`.

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::identity_propagation::{
    BackendDescriptor, IdentityPropagation, IdentityPropagationConfig, PropagatedCredential,
    PropagationError, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;

const BACKEND: &str = "lent";
const TOOL: &str = "lookup";

/// A mint that succeeds with `headers`, valid until `expires_at` (unix
/// seconds): none and never expiring for a call carrying no credential, one
/// long expired for a send its recheck refuses.
struct FixedMint {
    headers: Vec<(String, String)>,
    expires_at: i64,
}

#[async_trait::async_trait]
impl IdentityPropagation for FixedMint {
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        backend: &BackendDescriptor,
    ) -> Result<PropagatedCredential, PropagationError> {
        Ok(PropagatedCredential {
            headers: self.headers.clone(),
            expires_at: self.expires_at,
            expiry_synthetic: false,
            cache_binding: format!("{}@{}", identity.subject(), backend.audience),
            subject_key: identity.subject().to_owned(),
            audience: backend.audience.clone(),
            scopes: Vec::new(),
        })
    }
}

/// A streamable HTTP MCP peer on loopback; returns its URL and the
/// `tools/call` requests it received.
async fn peer() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let app = axum::Router::new().fallback(move |axum::Json(message): axum::Json<Value>| {
        let counted = Arc::clone(&counted);
        async move {
            let method = message["method"].as_str().unwrap_or_default().to_owned();
            let result = match method.as_str() {
                "tools/list" => json!({"tools": [{"name": TOOL,
                    "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}}]}),
                "tools/call" => {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    json!({"content": [{"type": "text", "text": "ok"}]})
                }
                _ => json!({}),
            };
            let id = message.get("id").cloned().unwrap_or(Value::Null);
            axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    (url, calls)
}

/// The router over one required per-user backend at `url`, minted by
/// `mint`, and its transparency log's directory.
async fn gateway(
    url: String,
    mint: FixedMint,
) -> (axum::Router, (tempfile::TempDir, super::tests::FixtureDir)) {
    let (router, dirs, _meta) =
        gateway_in(url, mint, crate::config::InputSchemaEnforcement::Off).await;
    (router, dirs)
}

/// [`gateway`] with the backend's input-schema enforcement set to `mode`:
/// anything but `off` runs the argument-key check, whose cold fill lists
/// the backend first.
async fn gateway_in(
    url: String,
    mint: FixedMint,
    mode: crate::config::InputSchemaEnforcement,
) -> (
    axum::Router,
    (tempfile::TempDir, super::tests::FixtureDir),
    (
        Arc<crate::gateway::meta_mcp::MetaMcp>,
        Arc<crate::backend::Backend>,
    ),
) {
    gateway_named(BACKEND, url, mint, mode).await
}

/// [`gateway_in`] over a backend named `name`: a row reading process-wide
/// metrics needs a server label no parallel row shares.
async fn gateway_named(
    name: &str,
    url: String,
    mint: FixedMint,
    mode: crate::config::InputSchemaEnforcement,
) -> (
    axum::Router,
    (tempfile::TempDir, super::tests::FixtureDir),
    (
        Arc<crate::gateway::meta_mcp::MetaMcp>,
        Arc<crate::backend::Backend>,
    ),
) {
    let backend = Arc::new(crate::backend::Backend::new(
        name,
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "https://lent.internal".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            input_schema_enforcement: mode,
            ..BackendConfig::r2_off()
        },
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    assert!(
        registry.register(Arc::clone(&backend)),
        "the backend registers"
    );
    let mut meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&registry));
    meta.set_identity_propagation(Arc::new(mint));
    let log_dir = tempfile::tempdir().expect("a log directory");
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: log_dir
                    .path()
                    .join("audit.jsonl")
                    .to_string_lossy()
                    .into_owned(),
                key_id: "lend".to_string(),
                ..crate::security::transparency_log::TransparencyLogConfig::default()
            },
        ))
        .expect("the transparency log opens"),
    );
    meta.enable_transparency_log(Arc::clone(&log));
    let auth = crate::config::AuthConfig::default();
    let (mut state, store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = registry;
    let meta = Arc::new(meta);
    state_mut.meta_mcp = Arc::clone(&meta);
    state_mut.transparency_log = Some(log);
    (
        super::create_router(state),
        (log_dir, store),
        (meta, backend),
    )
}

/// POST a direct `tools/call` of [`TOOL`] as a verified caller, with the
/// modern protocol headers; returns the status and the parsed answer.
async fn call(router: &axum::Router) -> (axum::http::StatusCode, Value) {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": TOOL, "arguments": {"q": "x"},
                   "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                             "io.modelcontextprotocol/clientCapabilities": {}}}});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{BACKEND}"))
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", TOOL)
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request.extensions_mut().insert(VerifiedIdentity::for_test(
        "alpha".to_string(),
        "alpha@example.invalid".to_string(),
        None,
        vec![],
        "https://issuer.example.invalid".to_string(),
    ));
    let response = router.clone().oneshot(request).await.expect("an answer");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lent_only_call_carrying_no_credential_records_refused() {
    let (url, calls) = peer().await;
    let mint = FixedMint {
        headers: vec![],
        expires_at: i64::MAX,
    };
    let (router, dirs) = gateway(url, mint).await;
    let (status, answer) = call(&router).await;
    // Premise: refused by the lender, for this reason, and never sent. A
    // refusal for any other reason means no route reaches the lender.
    assert!(
        answer.to_string().contains("this call carried none"),
        "premise: the lender's refusal: {status} {answer}"
    );
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(
        answer["error"]["code"], -32001,
        "the code is unchanged: {answer}"
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    let raw = std::fs::read_to_string(dirs.0.path().join("audit.jsonl")).unwrap_or_default();
    let delivered: Vec<Value> = raw
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry["event"] == "response_delivery_attempt")
        .collect();
    let [one] = delivered.as_slice() else {
        panic!("premise: one delivery record: {delivered:?}");
    };
    assert_eq!(one["response_effect"], "refused", "{one}");
    // The check is about the caller's own credential, which no decision kind
    // names yet: refused with kind `unrecorded`, never `default_allow`.
    // Flips to that kind when an identity-standing kind is added.
    let invocations: Vec<Value> = raw
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| {
            entry.get("tool").is_some() && entry["event"] != "response_delivery_attempt"
        })
        .collect();
    let [invocation] = invocations.as_slice() else {
        panic!("premise: one invocation record: {invocations:?}");
    };
    assert_eq!(invocation["decision"]["kind"], "unrecorded", "{invocation}");
}

/// A send whose credential fails its per-send recheck (published as expired
/// long ago) is refused by the lender with `Forbidden`, and `/mcp/{name}`
/// answers it 403 with -32001, not 500, recording it refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_its_recheck_refuses_answers_403_and_records_refused() {
    let (url, calls) = peer().await;
    let mint = FixedMint {
        headers: vec![("Authorization".to_string(), "Bearer lapsed".to_string())],
        expires_at: 1,
    };
    let (router, dirs) = gateway(url, mint).await;
    let (status, answer) = call(&router).await;
    // Premise: refused by the per-send recheck, for this reason, and never
    // sent. A refusal for any other reason (the mint refusing the expired
    // credential first) does not reach the lender.
    assert!(
        answer.to_string().contains("per-user send refused"),
        "premise: the recheck's refusal: {status} {answer}"
    );
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{answer}");
    assert_eq!(answer["error"]["code"], -32001, "{answer}");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    let raw = std::fs::read_to_string(dirs.0.path().join("audit.jsonl")).unwrap_or_default();
    let delivered: Vec<Value> = raw
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry["event"] == "response_delivery_attempt")
        .collect();
    let [one] = delivered.as_slice() else {
        panic!("premise: one delivery record: {delivered:?}");
    };
    assert_eq!(one["response_effect"], "refused", "{one}");
    // The check is about the caller's own credential, which no decision kind
    // names yet: refused with kind `unrecorded`, never `default_allow`.
    // Flips to that kind when an identity-standing kind is added.
    let invocations: Vec<Value> = raw
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| {
            entry.get("tool").is_some() && entry["event"] != "response_delivery_attempt"
        })
        .collect();
    let [invocation] = invocations.as_slice() else {
        panic!("premise: one invocation record: {invocations:?}");
    };
    assert_eq!(invocation["decision"]["kind"], "unrecorded", "{invocation}");
}

/// POST a meta-route `gateway_invoke` of [`BACKEND`]'s [`TOOL`] as the same
/// verified caller; returns the status and the parsed answer.
async fn invoke(router: &axum::Router) -> (axum::http::StatusCode, Value) {
    let arguments = json!({"server": BACKEND, "tool": TOOL, "arguments": {"q": "x"}});
    meta_call(router, "gateway_invoke", arguments).await
}

/// POST a meta-route `tools/call` of the meta-tool `name` with `arguments`
/// as the verified caller; returns the status and the parsed answer.
async fn meta_call(
    router: &axum::Router,
    name: &str,
    arguments: Value,
) -> (axum::http::StatusCode, Value) {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": arguments,
                   "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                             "io.modelcontextprotocol/clientCapabilities": {}}}});
    post_mcp(router, &body).await
}

/// POST `body` to `/mcp` as the verified caller, with the modern headers its
/// method and name select; returns the status and the parsed answer.
async fn post_mcp(router: &axum::Router, body: &Value) -> (axum::http::StatusCode, Value) {
    let method = body["method"].as_str().unwrap_or_default();
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method);
    if let Some(field) = crate::protocol::headers::mcp_name_body_field(method)
        && let Some(name) = body
            .pointer(&format!("/params/{field}"))
            .and_then(Value::as_str)
    {
        builder = builder.header("mcp-name", name);
    }
    let mut request = builder
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request.extensions_mut().insert(VerifiedIdentity::for_test(
        "alpha".to_string(),
        "alpha@example.invalid".to_string(),
        None,
        vec![],
        "https://issuer.example.invalid".to_string(),
    ));
    let response = router.clone().oneshot(request).await.expect("an answer");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The one delivery record and the one invocation record the log holds.
fn records(log_dir: &tempfile::TempDir) -> (Value, Value) {
    let raw = std::fs::read_to_string(log_dir.path().join("audit.jsonl")).unwrap_or_default();
    let entries: Vec<Value> = raw
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .collect();
    let delivered: Vec<&Value> = entries
        .iter()
        .filter(|entry| entry["event"] == "response_delivery_attempt")
        .collect();
    let invocations: Vec<&Value> = entries
        .iter()
        .filter(|entry| {
            entry.get("tool").is_some() && entry["event"] != "response_delivery_attempt"
        })
        .collect();
    let ([delivery], [invocation]) = (delivered.as_slice(), invocations.as_slice()) else {
        panic!("premise: one delivery and one invocation record: {entries:?}");
    };
    ((*delivery).clone(), (*invocation).clone())
}

/// The meta route answers a lend refusal as the refusal it is: the
/// JSON-RPC error the direct route gives, with no tool result, no recovery
/// hint and nothing suggesting a retry, recorded refused.
async fn assert_meta_refusal(mint: FixedMint, premise: &str) {
    let (url, calls) = peer().await;
    let (router, dirs) = gateway(url, mint).await;
    let (status, answer) = invoke(&router).await;
    let text = answer.to_string();
    assert!(
        text.contains(premise),
        "premise: the lender's refusal: {status} {answer}"
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        answer["error"]["code"], -32001,
        "answered as a refusal, not a tool result: {status} {answer}"
    );
    assert!(answer.get("result").is_none(), "{answer}");
    assert!(
        !text.contains("_recovery") && !text.contains("retrying once is safe"),
        "no retry is suggested: {answer}"
    );
    let (delivery, invocation) = records(&dirs.0);
    assert_eq!(delivery["response_effect"], "refused", "{delivery}");
    assert_eq!(invocation["decision"]["kind"], "unrecorded", "{invocation}");
}

/// LEND.1-3: a lent-only call carrying no credential, on the meta route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_meta_call_carrying_no_credential_is_answered_as_a_refusal() {
    let mint = FixedMint {
        headers: vec![],
        expires_at: i64::MAX,
    };
    assert_meta_refusal(mint, "this call carried none").await;
}

/// LEND.1-3: a send its per-send recheck refuses, on the meta route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_meta_send_its_recheck_refuses_is_answered_as_a_refusal() {
    let mint = FixedMint {
        headers: vec![("Authorization".to_string(), "Bearer lapsed".to_string())],
        expires_at: 1,
    };
    assert_meta_refusal(mint, "per-user send refused").await;
}

/// LEND.2 on the direct route: its 403 suggests no retry (a control).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_lend_refusal_suggests_no_retry() {
    let (url, _calls) = peer().await;
    let mint = FixedMint {
        headers: vec![],
        expires_at: i64::MAX,
    };
    let (router, _dirs) = gateway(url, mint).await;
    let (status, answer) = call(&router).await;
    assert_eq!(
        status,
        axum::http::StatusCode::FORBIDDEN,
        "premise: {answer}"
    );
    let text = answer.to_string();
    assert!(
        !text.contains("_recovery") && !text.contains("retrying once is safe"),
        "no retry is suggested: {answer}"
    );
}

/// LEND.5: a cold fill the lender refuses (the call carries no credential)
/// answers as the dispatch's refusal under `mode`, never as "schema
/// unreadable" and never as a backend error result.
async fn assert_cold_fill_refusal(mode: crate::config::InputSchemaEnforcement) {
    let (url, calls) = peer().await;
    let mint = FixedMint {
        headers: vec![],
        expires_at: i64::MAX,
    };
    let (router, _dirs, _meta) = gateway_in(url, mint, mode).await;
    let (status, answer) = invoke(&router).await;
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "premise: nothing reached the backend: {status} {answer}"
    );
    assert_eq!(
        answer["error"]["code"], -32001,
        "answered as the refusal, under {mode:?}: {status} {answer}"
    );
    assert!(
        !answer.to_string().contains("input schema"),
        "not the unreadable-schema answer: {answer}"
    );
    assert!(
        answer.to_string().contains("this call carried none"),
        "the lender's own refusal reaches the caller: {answer}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cold_fill_refused_by_the_lender_is_a_refusal_under_closed() {
    assert_cold_fill_refusal(crate::config::InputSchemaEnforcement::Closed).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cold_fill_refused_by_the_lender_is_a_refusal_under_standard() {
    assert_cold_fill_refusal(crate::config::InputSchemaEnforcement::Standard).await;
}

/// LEND.6: a refusal left out of the error budget is still a recorded
/// invocation: the invocation counter (status `error`) and the duration
/// histogram each count it, once. A lent-only call carrying no credential is
/// refused at the route stage's catalogue fill, before any dispatch, so this
/// row covers the refused-fill accounting; a send refused at the dispatch has
/// its own row (`bridge_send_refusal_tests`). The metrics are process-wide, so
/// the row's backend has a name of its own: other rows refuse fills of
/// [`BACKEND`] in parallel, which the same metrics count.
#[cfg(feature = "metrics")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_meta_lend_refusal_is_still_recorded_as_an_invocation() {
    use crate::metrics::series_value;
    const ALONE: &str = "lent-metrics";
    crate::metrics::install();
    let (url, calls) = peer().await;
    let mint = FixedMint {
        headers: vec![],
        expires_at: i64::MAX,
    };
    let (router, _dirs, _) =
        gateway_named(ALONE, url, mint, crate::config::InputSchemaEnforcement::Off).await;
    let server = format!("server=\"{ALONE}\"");
    let read = || {
        let text = crate::metrics::render();
        (
            series_value(
                &text,
                "mcp_tool_invocations_total",
                &[&server, "status=\"error\""],
            ),
            series_value(
                &text,
                "mcp_tool_invocation_duration_seconds_count",
                &[&server],
            ),
        )
    };
    assert_eq!(read(), (0.0, 0.0), "premise: no series for the backend yet");
    let arguments = json!({"server": ALONE, "tool": TOOL, "arguments": {"q": "x"}});
    let (status, answer) = meta_call(&router, "gateway_invoke", arguments).await;
    assert!(
        answer.to_string().contains("this call carried none"),
        "premise: the lender's refusal: {status} {answer}"
    );
    assert_eq!(answer["error"]["code"], -32001, "{answer}");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        read(),
        (1.0, 1.0),
        "one invocation with status error, and its duration"
    );
}

/// LEND.6, end to end: refusals the real per-user lender makes, on either
/// route, record nothing in the backend's or the tool's error-budget
/// window, so no number of them can disable the tool for every caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lend_refusals_on_either_route_record_no_budget_sample() {
    let (url, calls) = peer().await;
    let mint = FixedMint {
        headers: vec![],
        expires_at: i64::MAX,
    };
    let (router, _dirs, (meta, _)) =
        gateway_in(url, mint, crate::config::InputSchemaEnforcement::Off).await;
    // Past every window's threshold: the backend's minimum sample count is
    // the larger, and two more refusals than it would already be judged.
    let past = crate::kill_switch::ErrorBudgetConfig::default().min_samples + 2;
    let mut answers = Vec::new();
    for n in 0..past {
        answers.push(if n % 2 == 0 {
            invoke(&router).await
        } else {
            call(&router).await
        });
    }
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    for (n, (status, answer)) in answers.iter().enumerate() {
        assert!(
            answer.to_string().contains("this call carried none"),
            "refusal {n} of {past} is not the lender's (disabled by its own refusals?): {status} {answer}"
        );
    }
    let switch = meta.kill_switch();
    assert_eq!(switch.window_counts(BACKEND), (0, 0), "the backend window");
    assert_eq!(
        switch.capability_window_counts(BACKEND, TOOL),
        (0, 0),
        "the tool's window"
    );
}

/// A modern request of `method` with `params`, declaring tasks.
fn task_request(method: &str, mut params: Value) -> Value {
    use crate::gateway::meta_mcp::upstream::TASKS_EXTENSION;
    use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"extensions": {TASKS_EXTENSION: {}}},
        IDEMPOTENCY_KEY_META: "lend-task-1",
    });
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
}

/// LEND.5 on a task: the worker's dispatch judges the caller's slot itself
/// (the route stage's memo judged only the creating request), so its cold
/// fill is the dispatch check's own (`r2_check::answer_refused_fill`). The
/// lender refuses that fill, nothing is sent, and the worker's dispatch is
/// answered and recorded as the refusal, never as a backend error result.
/// Read from the audit log, not `tasks/get`: a task read judges the slot
/// again, and its answer is not this row's subject.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_task_workers_cold_fill_refused_by_the_lender_is_recorded_refused() {
    let (url, calls) = peer().await;
    let mint = FixedMint {
        headers: vec![],
        expires_at: i64::MAX,
    };
    let (router, dirs, (_meta, backend)) =
        gateway_in(url, mint, crate::config::InputSchemaEnforcement::Closed).await;
    let create = task_request(
        "tools/call",
        json!({"name": "gateway_invoke", "task": {},
               "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"q": "x"}}}),
    );
    let (status, created) = post_mcp(&router, &create).await;
    assert!(
        created.pointer("/result/taskId").is_some(),
        "premise: a task handle: {status} {created}"
    );
    // The worker's records, once its dispatch settles: polled, under a hang
    // guard well past any settle time.
    let audit = dirs.0.path().join("audit.jsonl");
    let worker_records = || -> Vec<Value> {
        std::fs::read_to_string(&audit)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|entry| entry["tool"] == TOOL)
            .collect()
    };
    let settled = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let worker = worker_records();
            if worker
                .iter()
                .any(|entry| entry.get("response_effect").is_some())
            {
                return worker;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await;
    let worker = settled.unwrap_or_else(|_| {
        panic!(
            "the worker's dispatch never settled within 30 s: {:?}",
            worker_records()
        )
    });
    let [invocation, delivery] = worker.as_slice() else {
        panic!(
            "the worker's dispatch is recorded as a refusal, an invocation and a delivery: {worker:?}"
        );
    };
    assert_eq!(invocation["error_code"], -32001, "{invocation}");
    assert_eq!(
        delivery["response_effect"], "refused",
        "the worker's dispatch is recorded refused: {delivery}"
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    // One refusal at the creating request's verdict, one at the worker's own
    // dispatch: no strategy refills a refused slot.
    let refusals: Vec<usize> = backend.lend_refusals.lock().values().copied().collect();
    assert_eq!(refusals, [2], "the caller's binding, refused twice");
}

/// LEND.5's boundary: a stale list refreshed under a lend refusal still
/// answers from what the slot holds (design E). The held schema declares
/// only `q`, so the call's undeclared key is refused from the stale list;
/// the refresh's refusal never replaces that answer, and nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_list_refreshed_under_a_lend_refusal_still_answers_from_the_cache() {
    let (url, calls) = peer().await;
    let mint = FixedMint {
        headers: vec![],
        expires_at: i64::MAX,
    };
    let (router, _dirs, (_meta, backend)) =
        gateway_in(url, mint, crate::config::InputSchemaEnforcement::Closed).await;
    // The caller's binding: the mint's own (`FixedMint::propagate`).
    let binding = "alpha@https://lent.internal";
    let held: crate::protocol::Tool = serde_json::from_value(json!({"name": TOOL,
        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}}))
    .expect("a tool");
    backend.store_per_user_tools_for_test(binding, vec![held]);
    backend.stale_per_user_tools_for_test(binding);
    let arguments = json!({"server": BACKEND, "tool": TOOL,
                           "arguments": {"q": "x", "undeclared": 1}});
    let (status, answer) = meta_call(&router, "gateway_invoke", arguments).await;
    let refusals: Vec<usize> = backend.lend_refusals.lock().values().copied().collect();
    assert!(
        !refusals.is_empty(),
        "premise: the stale list's refresh was refused by the lender: {status} {answer}"
    );
    assert!(
        !answer.to_string().contains("this call carried none"),
        "answered from the held list, not by the refresh's refusal: {status} {answer}"
    );
    assert!(
        answer.to_string().contains("undeclared"),
        "the held schema refused the key it does not declare: {status} {answer}"
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}
