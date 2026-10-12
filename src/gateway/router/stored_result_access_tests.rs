// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Probe rows for "a stored result must not outlive the caller's access"
//! (MIK-8356 delta review). Written to compile on the release line and on the
//! MIK-8356 head alike, so one file classifies each claim as pre-existing or
//! introduced.

use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx, fixture, send_with_headers};

const MARKER: &str = "stored-output-probe-8356";

fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
    })
}

/// A keyed modern `gateway_invoke` of `alpha:read`, offered as a task.
async fn task_call(fx: &Fx, key: &str) -> Value {
    let name = "gateway_invoke";
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let params = json!({
        "name": name,
        "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
        "task": {},
        "_meta": meta,
    });
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", name),
    ];
    send_with_headers(fx, "/mcp", "k-std", "tools/call", params, None, &headers)
        .await
        .1
}

/// `method` (`tasks/get` or `tasks/result`) for task `id`, as `k-std`.
async fn task_read(fx: &Fx, method: &str, id: &str) -> Value {
    let mut params = json!({ "taskId": id });
    params["_meta"] = modern_meta();
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", method),
        ("mcp-name", id),
    ];
    send_with_headers(fx, "/mcp", "k-std", method, params, None, &headers)
        .await
        .1
}

/// Polls `tasks/get` (up to 10 s) until the task is terminal.
async fn wait_terminal(fx: &Fx, id: &str) -> Value {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let got = task_read(fx, "tasks/get", id).await;
        let status = got.pointer("/result/status").and_then(Value::as_str);
        if matches!(status, Some("completed" | "failed" | "cancelled"))
            || tokio::time::Instant::now() >= deadline
        {
            return got;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// P1 (task delivery): `k-std` makes a task of `alpha:read`, which completes
/// with the backend's output. `alpha` then withholds `read` (its description
/// is blocked, as a poisoned listing leaves it). Reading the task back must
/// not deliver the stored output of a tool the caller can no longer see or
/// call. RED where task reads deliver stored output without judging the
/// target's current visibility.
#[tokio::test]
async fn p1_task_reads_do_not_deliver_output_of_a_withheld_tool() {
    let fx = fixture(Answer::Text(MARKER), |_| {}).await;
    let made = task_call(&fx, "p1-task").await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let done = wait_terminal(&fx, &id).await;
    let result = task_read(&fx, "tasks/result", &id).await;
    assert!(
        result.to_string().contains(MARKER) || done.to_string().contains(MARKER),
        "premise: the completed task carries the backend's output: {done} / {result}"
    );
    fx.state
        .backends
        .get("alpha")
        .expect("alpha is registered")
        .block_tool_for_test("read");
    for method in ["tasks/get", "tasks/result"] {
        let read = task_read(&fx, method, &id).await;
        assert!(
            !read.to_string().contains(MARKER),
            "P1 {method}: stored output of a withheld tool was delivered: {read}"
        );
    }
}

/// The sole operator's router over the managed-account backend, connected,
/// with `read` surfaced and a valid shared listing (as the MIK-8356 managed
/// rows build it, without the audit log).
mod revoked {
    use std::sync::Arc;

    use axum::body::to_bytes;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use crate::config::{ApiKeyConfig, AuthConfig, SurfacedToolConfig, api_key_digest_spec};
    use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
        BACKEND, Binding, DirectAccountGateway,
    };

    const KEY: &str = "sole-operator-key";
    pub(super) const TOOL: &str = "read";

    pub(super) struct Fx {
        pub(super) router: axum::Router,
        pub(super) gateway: DirectAccountGateway,
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

    pub(super) async fn fixture() -> Fx {
        let auth = sole_operator();
        let mut gateway = DirectAccountGateway::new(auth.clone(), &Binding::Connected);
        let (mut state, store) = super::super::tests::test_router_app_state_with_auth(&auth).await;
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
            router: super::super::create_router(state),
            gateway,
            _store: store,
        }
    }

    /// A keyed modern `gateway_invoke` of [`TOOL`] on the backend.
    pub(super) async fn keyed_invoke(fx: &Fx, key: &str) -> Value {
        let mut meta = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "extensions": {"io.modelcontextprotocol/tasks": {}}
            },
        });
        meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
        let body = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "gateway_invoke",
                "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
                "_meta": meta}});
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {KEY}"))
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "tools/call")
            .header("mcp-name", "gateway_invoke")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let response = fx.router.clone().oneshot(request).await.unwrap();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }
}

/// P2 (revoked grant, keyed replay): the sole operator's keyed
/// `gateway_invoke` dispatches while its managed grant is connected; the
/// grant is then revoked. The same call with the same key must not be served
/// the stored output: the operator no longer has the account, so it gets the
/// account's answer (not connected), never the earlier result. RED where an
/// idempotent replay or retained result is served before the credential is
/// resolved.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2_keyed_replay_after_the_grant_is_revoked_serves_no_stored_output() {
    let fx = revoked::fixture().await;
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let first = revoked::keyed_invoke(&fx, "p2-replay").await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: the connected call returns the backend's output: {first}"
    );
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.revoke_operator_grant_for_probe().await;
    let replay = revoked::keyed_invoke(&fx, "p2-replay").await;
    assert!(
        !replay.to_string().contains(MARKER),
        "P2: a revoked grant's keyed retry was served the stored output: {replay}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "P2: the retry reached the backend: {replay}"
    );
}

/// P1b: [`p1_task_reads_do_not_deliver_output_of_a_withheld_tool`] with
/// `read` withheld by its listing instead: `alpha` relists it with a
/// structurally invalid schema, so the catalogue withholds it (no descriptor
/// block). Reading the task back must not deliver its stored output.
#[tokio::test]
async fn p1b_task_reads_do_not_deliver_output_of_a_tool_the_listing_withholds() {
    let fx = fixture(Answer::Text(MARKER), |_| {}).await;
    let made = task_call(&fx, "p1b-task").await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let done = wait_terminal(&fx, &id).await;
    let result = task_read(&fx, "tasks/result", &id).await;
    assert!(
        result.to_string().contains(MARKER) || done.to_string().contains(MARKER),
        "premise: the completed task carries the backend's output: {done} / {result}"
    );
    let withheld: crate::protocol::Tool = serde_json::from_value(json!({
        "name": "read", "inputSchema": {"type": "object", "properties": 7}
    }))
    .expect("a tool");
    fx.state
        .backends
        .get("alpha")
        .expect("alpha is registered")
        .store_shared_tools_for_test(vec![withheld]);
    for method in ["tasks/get", "tasks/result"] {
        let read = task_read(&fx, method, &id).await;
        assert!(
            !read.to_string().contains(MARKER),
            "P1b {method}: stored output of a withheld tool was delivered: {read}"
        );
    }
}
