// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392.STORED.1 T10 (batch A): a stored task read by the sole operator
//! whose managed-account grant was revoked after the task ran answers -32601,
//! as a name the operator can no longer reach does. The control reads the
//! same task while the grant is live and is served its output.

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
const MARKER: &str = "stored-output-8392-t10";

struct Fx {
    router: axum::Router,
    /// For reading a task record past the stored-read check (W2).
    state: Arc<super::AppState>,
    gateway: DirectAccountGateway,
    /// The transparency log this fixture's `MetaMcp` writes (MIK-8392 B1).
    audit_path: std::path::PathBuf,
    _audit: tempfile::TempDir,
    _store: crate::gateway::router::tests::FixtureDir,
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

/// The sole operator's router over the managed-account backend, connected,
/// with `read` surfaced and a valid shared listing (the probe's fixture).
async fn fixture() -> Fx {
    let auth = sole_operator();
    let mut gateway = DirectAccountGateway::new(auth.clone(), &Binding::Connected);
    let (mut state, store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let audit = tempfile::tempdir().expect("a log directory");
    let audit_path = audit.path().join("audit.jsonl");
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: audit_path.to_string_lossy().into_owned(),
                key_id: "8392".to_string(),
                ..crate::security::transparency_log::TransparencyLogConfig::default()
            },
        ))
        .expect("open log"),
    );
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = gateway.backends();
    let mut meta = gateway
        .take_meta()
        .with_surfaced_tools(vec![SurfacedToolConfig {
            server: BACKEND.to_string(),
            tool: TOOL.to_string(),
        }]);
    meta.enable_transparency_log(Arc::clone(&log));
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(log);
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
        router: super::create_router(Arc::clone(&state)),
        state,
        gateway,
        audit_path,
        _audit: audit,
        _store: store,
    }
}

fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
    })
}

async fn send(fx: &Fx, method: &str, name: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": method, "params": params});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {KEY}"))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method)
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    let response = fx.router.clone().oneshot(request).await.expect("an answer");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn task_get(fx: &Fx, id: &str) -> Value {
    send(
        fx,
        "tasks/get",
        id,
        json!({"taskId": id, "_meta": modern_meta()}),
    )
    .await
}

/// A name no backend serves, swapped for [`TOOL`] in its answer.
const MISSING: &str = "no_such_tool_8392";

/// The gateway's own answer to a name that matches no tool on `/mcp`, with
/// the missing name replaced by [`TOOL`]: `read` is surfaced in this fixture,
/// so it cannot itself be the missing name (as the MIK-8387 rows mask names).
async fn absent_twin(fx: &Fx) -> Value {
    let twin = send(
        fx,
        "tools/call",
        MISSING,
        json!({"name": MISSING, "arguments": {}, "_meta": modern_meta()}),
    )
    .await;
    let error = twin
        .get("error")
        .unwrap_or_else(|| panic!("premise: an absent name is refused: {twin}"));
    serde_json::from_str(&error.to_string().replace(MISSING, TOOL)).expect("JSON")
}

/// The blocked read answers exactly as an absent name does.
async fn assert_answers_as_absent(fx: &Fx, read: &Value, row: &str) {
    assert_eq!(
        read.get("error"),
        Some(&absent_twin(fx).await),
        "{row}: a blocked stored read answers exactly as an absent name: {read}"
    );
}

/// T10: grant revoked after the task ran, the shared listing still offering
/// the tool. Red on the release line: tasks/get delivers the stored output.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t10_a_stored_read_after_the_grant_is_revoked_answers_absent() {
    let fx = fixture().await;
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("s1-t10");
    let made = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
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
        let got = task_get(&fx, &id).await;
        if got.to_string().contains(MARKER) || std::time::Instant::now() >= bound {
            break got;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    assert!(
        control.to_string().contains(MARKER),
        "control: while the grant is live the stored output is served: {control}"
    );
    fx.gateway.revoke_operator_grant_for_test().await;
    let read = task_get(&fx, &id).await;
    assert_answers_as_absent(&fx, &read, "T10").await;
    assert!(
        !read.to_string().contains(MARKER),
        "T10: output delivered: {read}"
    );
}

/// A plain backend (no managed account) whose one tool answers `plain-ok`.
/// With `hold`, each `tools/call` waits for one permit first.
#[derive(Default)]
struct PlainBackend {
    hold: Option<Arc<tokio::sync::Semaphore>>,
    /// `tools/call`s that arrived, counted before the hold (MIK-8392 WM1).
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for PlainBackend {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let id = crate::protocol::RequestId::Number(1);
        if method == "tools/call"
            && let Some(hold) = &self.hold
        {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            hold.acquire().await.expect("the hold is open").forget();
        } else if method == "tools/call" {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        let result = if method == "tools/list" {
            json!({"tools": [{"name": "echo", "inputSchema": {"type": "object"}}]})
        } else {
            json!({"content": [{"type": "text", "text": "plain-ok"}], "isError": false})
        };
        Ok(crate::protocol::JsonRpcResponse::success(id, result))
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

const PLAIN: &str = "plain";

/// Register [`PlainBackend`] as `plain`, its listing warm.
fn register_plain(fx: &Fx) {
    register_plain_with(fx, PlainBackend::default());
}

/// Register `plain` as `plain`, its listing warm.
fn register_plain_with(fx: &Fx, plain: PlainBackend) {
    let backend = Arc::new(crate::backend::Backend::new(
        PLAIN,
        crate::config::BackendConfig::default(),
        &{
            let mut failsafe = crate::config::FailsafeConfig::default();
            failsafe.rate_limit.enabled = false;
            failsafe
        },
        std::time::Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(plain));
    let tool: crate::protocol::Tool =
        serde_json::from_value(json!({"name": "echo", "inputSchema": {"type": "object"}}))
            .expect("a tool");
    backend.store_shared_tools_for_test(vec![tool]);
    assert!(fx.gateway.backends().register(backend), "plain registered");
}

/// T10p (lead, from MIK-8406's seats): a plan task whose SECOND recorded
/// target is the managed-account backend. The account is revoked after the
/// plan completes; tasks/get answers -32601 and delivers no stored output.
/// Every recorded target is judged, not only the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t10p_a_plan_task_whose_second_targets_account_is_revoked_answers_absent() {
    let fx = fixture().await;
    register_plain(&fx);
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("s1-t10p");
    let made = send(
        &fx,
        "tools/call",
        "gateway_execute",
        json!({"name": "gateway_execute",
            "arguments": {"chain": [
                {"tool": format!("{PLAIN}:echo"), "arguments": {}},
                {"tool": format!("{BACKEND}:{TOOL}"), "arguments": {"folder": "inbox"}}
            ]},
            "task": {}, "_meta": meta}),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a plan task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let control = loop {
        let got = task_get(&fx, &id).await;
        if got.to_string().contains(MARKER) || std::time::Instant::now() >= bound {
            break got;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    assert!(
        control.to_string().contains(MARKER),
        "control: while the grant is live the plan's stored output is served: {control}"
    );
    fx.gateway.revoke_operator_grant_for_test().await;
    let read = task_get(&fx, &id).await;
    assert_answers_as_absent(&fx, &read, "T10p").await;
    assert!(
        !read.to_string().contains(MARKER),
        "T10p: output delivered: {read}"
    );
}

/// The JSON payloads of an open SSE body, read block by block.
struct Frames {
    body: axum::body::BodyDataStream,
    buffer: Vec<u8>,
}

impl Frames {
    async fn next(&mut self) -> Value {
        use futures::StreamExt as _;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(end) = self.buffer.windows(2).position(|pair| pair == b"\n\n") {
                let block: Vec<u8> = self.buffer.drain(..end + 2).collect();
                let text = String::from_utf8(block).expect("a frame is UTF-8");
                let data: Vec<&str> = text
                    .lines()
                    .filter_map(|l| l.strip_prefix("data: "))
                    .collect();
                if !data.is_empty() {
                    return serde_json::from_str(&data.join("\n")).expect("a frame is JSON");
                }
                continue;
            }
            let chunk = tokio::time::timeout_at(deadline, self.body.next())
                .await
                .expect("a frame within the bound")
                .expect("the stream stays open")
                .expect("the body reads");
            self.buffer.extend_from_slice(&chunk);
        }
    }
}

/// T10pf (a2a-1, MIK-8406): T10p's frame twin. The plan's account step runs
/// first while the grant is live; the plain step is then held, the grant
/// revoked, and the plain step released. The completion frame is built after
/// the revoke, so it must carry status only. Control: the same plan without
/// the revoke carries the output in its frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t10pf_a_plan_tasks_frame_after_its_accounts_revoke_carries_status_only() {
    for revoke in [false, true] {
        let fx = fixture().await;
        let hold = Arc::new(tokio::sync::Semaphore::new(0));
        register_plain_with(
            &fx,
            PlainBackend {
                hold: Some(Arc::clone(&hold)),
                ..PlainBackend::default()
            },
        );
        fx.gateway.answer_next(json!({
            "content": [{"type": "text", "text": MARKER}], "isError": false
        }));
        let mut meta = modern_meta();
        meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(format!("s1-t10pf-{revoke}"));
        let made = send(
            &fx,
            "tools/call",
            "gateway_execute",
            json!({"name": "gateway_execute",
                "arguments": {"chain": [
                    {"tool": format!("{BACKEND}:{TOOL}"), "arguments": {"folder": "inbox"}},
                    {"tool": format!("{PLAIN}:echo"), "arguments": {}}
                ]},
                "task": {}, "_meta": meta}),
        )
        .await;
        let id = made
            .pointer("/result/taskId")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("premise: a plan task was made: {made}"))
            .to_owned();
        let listen = json!({"jsonrpc": "2.0", "id": 7501, "method": "subscriptions/listen",
            "params": {"taskIds": [&id], "_meta": modern_meta()}});
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {KEY}"))
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "subscriptions/listen")
            .body(axum::body::Body::from(listen.to_string()))
            .expect("a request");
        let response = fx.router.clone().oneshot(request).await.expect("an answer");
        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "premise: listen admitted"
        );
        let mut frames = Frames {
            body: response.into_body().into_data_stream(),
            buffer: Vec::new(),
        };
        let _acknowledged = frames.next().await;
        let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while fx.gateway.tool_calls().is_empty() && std::time::Instant::now() < bound {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            !fx.gateway.tool_calls().is_empty(),
            "premise: the account step ran"
        );
        if revoke {
            fx.gateway.revoke_operator_grant_for_test().await;
        }
        hold.add_permits(1);
        let completed = loop {
            let frame = frames.next().await;
            if frame.pointer("/params/status") == Some(&json!("completed")) {
                break frame;
            }
        };
        let carries = completed.to_string().contains(MARKER);
        if revoke {
            assert!(
                !carries,
                "T10pf: the frame carries a revoked plan's output: {completed}"
            );
        } else {
            assert!(
                carries,
                "control: the frame carries the plan's output: {completed}"
            );
            // N1 (M16): the frame is read outside any request scope, opens its
            // own memo, and its account pre-pass ran (the N0 count stays 0).
            assert_eq!(
                fx.gateway
                    .backends()
                    .get(BACKEND)
                    .expect("the backend")
                    .unfilled_outcome_reads
                    .load(std::sync::atomic::Ordering::SeqCst),
                0,
                "N1: the frame's pre-pass ran"
            );
        }
    }
}

/// A task of the operator's `read` that asked for input and parked, with the
/// request metadata that made it (reused for the resume).
async fn parked_input_task(fx: &Fx) -> (String, Value) {
    fx.gateway.answer_next(json!({
        "resultType": "input_required",
        "inputRequests": {"confirm": {"method": "elicitation/create",
            "params": {"message": "confirm?", "requestedSchema": {"type": "object", "properties": {}}}}},
        "requestState": "backend-state-w2"
    }));
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("s1-w2");
    meta["io.modelcontextprotocol/clientCapabilities"]["elicitation"] = json!({});
    let made = send(
        fx,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
            "task": {}, "_meta": meta.clone()}),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let got = task_get(fx, &id).await;
        if got.pointer("/result/status") == Some(&json!("input_required")) {
            break;
        }
        assert!(
            std::time::Instant::now() < bound,
            "premise: the task parks on its input round: {got}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    (id, meta)
}

/// W2 (lead, 2026-10-12): a credential resolved before an input-round pause
/// is never reused after it. The task's call asks for input and parks; the
/// account is revoked during the round; the client's answer resumes the
/// task. The resume opens a fresh memo, so it resolves again and is refused:
/// the backend sees no second call, and no output is delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w2_a_resume_after_the_account_is_revoked_during_the_input_round_is_refused() {
    let fx = fixture().await;
    let (id, meta) = parked_input_task(&fx).await;
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.revoke_operator_grant_for_test().await;
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let _ = send(
        &fx,
        "tasks/update",
        &id,
        json!({"taskId": id, "inputResponses": {"confirm": {"action": "accept", "content": {}}},
            "_meta": meta}),
    )
    .await;
    // Observed in the store, not through tasks/get: STORED.1 refuses a
    // revoked account's stored read (-32601), so tasks/get cannot show the
    // settle. Bounded: a resume that hangs fails here.
    let store = &fx.state.task_executor.service.store;
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let status = store.status_for_test(&id);
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
            "W2: the resumed task never settled after the revoke: {status:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let digest = store
        .owner_digest_for_test(&id)
        .expect("the task has an owner");
    let committed = store.get(&digest, &id).expect("the settled task reads");
    let settled = serde_json::to_value(committed.task.wire()).expect("JSON");
    assert_eq!(
        settled.get("status"),
        Some(&json!("failed")),
        "W2: a resume after the revoke ends refused, as failed: {settled}"
    );
    // The oracle is independent of the resume: a LIVE call of the same tool
    // under the same revoked account (the AccountReconnectRequired path). The
    // task's recorded error must be that answer's code and message.
    let live = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
            "_meta": modern_meta()}),
    )
    .await;
    let live_error = live
        .get("error")
        .unwrap_or_else(|| panic!("premise: the live call is refused after the revoke: {live}"));
    let recorded = settled
        .get("error")
        .unwrap_or_else(|| panic!("W2: the failed task records its error: {settled}"));
    assert_eq!(
        (recorded.get("code"), recorded.get("message")),
        (live_error.get("code"), live_error.get("message")),
        "W2: the resume refuses as the live call does: task {settled} vs live {live}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "W2: the resume reached the backend after the revoke: {settled}"
    );
    assert!(
        !settled.to_string().contains(MARKER),
        "W2: the resumed output was delivered after the revoke: {settled}"
    );
}

/// Ub (lead ruling 2026-10-12): a verified caller whose subject is empty can
/// never bind the managed account. Its stored read answers exactly what its
/// live tools/call answers (byte-equal error, never "retryable"), with
/// nothing dispatched and no custody read. Mutant: `unbindable` always false
/// turns the read retryable, and this row red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ub_an_unbindable_callers_stored_read_answers_its_live_refusal() {
    let auth = AuthConfig::default();
    let mut gateway = DirectAccountGateway::new(auth.clone(), &Binding::Connected);
    let (mut state, _store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = gateway.backends();
    state_mut.meta_mcp =
        Arc::new(
            gateway
                .take_meta()
                .with_surfaced_tools(vec![SurfacedToolConfig {
                    server: BACKEND.to_string(),
                    tool: TOOL.to_string(),
                }]),
        );
    let router = super::create_router(Arc::clone(&state));
    let nobody = |method: &str, name: &str, params: Value| {
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
        request
            .extensions_mut()
            .insert(crate::key_server::oidc::VerifiedIdentity {
                subject: String::new(),
                email: "nobody@example.invalid".to_string(),
                name: None,
                groups: vec![],
                issuer: "https://issuer.example.invalid".to_string(),
            });
        let router = router.clone();
        async move {
            let response = router.oneshot(request).await.expect("an answer");
            let bytes = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("a body");
            serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null)
        }
    };
    let call = json!({"name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
        "_meta": modern_meta()});
    let mut tasked = call.clone();
    tasked["task"] = json!({});
    tasked["_meta"][crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("s1-ub");
    let made = nobody("tools/call", "gateway_invoke", tasked).await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while state
        .task_executor
        .service
        .store
        .status_for_test(&id)
        .is_some_and(|status| status == crate::protocol::tasks::TaskStatus::Working)
    {
        assert!(
            std::time::Instant::now() < bound,
            "premise: the task settles"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let reads = gateway.resolves();
    let read = nobody(
        "tasks/get",
        &id,
        json!({"taskId": id, "_meta": modern_meta()}),
    )
    .await;
    let live = nobody("tools/call", "gateway_invoke", call).await;
    let live_error = live
        .get("error")
        .unwrap_or_else(|| panic!("premise: the live call is refused: {live}"));
    assert_eq!(
        read.get("error"),
        Some(live_error),
        "Ub: the stored read answers the live call's refusal: {read}"
    );
    assert_eq!(gateway.dispatched(), 0, "Ub: nothing dispatched");
    assert_eq!(gateway.resolves(), reads, "Ub: no custody read");
}

#[path = "stored_read_account_lease_tests.rs"]
mod lease;

#[path = "stored_read_ub_audit_tests.rs"]
mod ub_audit;

#[path = "stored_read_busy_nonce_tests.rs"]
mod busy_nonce;

#[path = "stored_read_busy_parity_tests.rs"]
mod busy_parity;

#[path = "stored_read_capability_busy_tests.rs"]
mod capability_busy;
/// MIK-8412: what the caller verdict adds to a signed nonce refusal on `/mcp`.
mod http_nonce_alloc;

#[path = "stored_read_account_send_tests.rs"]
mod sends;
