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
    gateway: DirectAccountGateway,
    _store: tempfile::TempDir,
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

/// The sole operator's router over the managed-account backend, connected,
/// with `read` surfaced and a valid shared listing (the probe's fixture).
async fn fixture() -> Fx {
    let auth = sole_operator();
    let mut gateway = DirectAccountGateway::new(auth.clone(), &Binding::Connected);
    let (mut state, store) = super::tests::test_router_app_state_with_auth(&auth).await;
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
    assert_eq!(
        read.pointer("/error/code"),
        Some(&json!(-32601)),
        "T10: a revoked account's stored read answers as an absent name: {read}"
    );
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
            hold.acquire().await.expect("the hold is open").forget();
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
    assert_eq!(
        read.pointer("/error/code"),
        Some(&json!(-32601)),
        "T10p: a revoked second target's stored plan read answers absent: {read}"
    );
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
        }
    }
}
