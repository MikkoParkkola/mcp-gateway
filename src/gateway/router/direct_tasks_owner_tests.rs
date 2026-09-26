// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F1 (#1442, MIK-7596): `tasks/*` on `POST /mcp/{name}` never reach the backend.
//!
//! Two callers allowed on one backend share its static credential, so the
//! backend sees one principal. Forwarding `tasks/*` verbatim let caller B read
//! or cancel caller A's backend task. The gateway's owner-checked task arms
//! serve `/mcp` only, so this route refuses every `tasks/*` method with -32601
//! before anything is forwarded.

use std::sync::Arc;
use std::time::Duration;

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use super::tests::test_router_app_state_with_auth;
use crate::backend::Backend;
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig};
use crate::protocol::{JsonRpcResponse, RequestId};

const KEY_A: &str = "key-f1-caller-a";
const KEY_B: &str = "key-f1-caller-b";
/// Scoped to another backend: it must keep getting the scope refusal.
const KEY_C: &str = "key-f1-other-scope";
const DIRECT: &str = "/mcp/shared";
/// The backend task id caller A's `tools/call` creates.
const TASK_A: &str = "bt-A";
/// A's task result; it must never appear in a reply to B.
const SECRET_A: &str = "secret-result-of-caller-a";

/// A backend that supports tasks. It records every method it receives.
struct TaskBackend {
    seen: parking_lot::Mutex<Vec<String>>,
}

impl TaskBackend {
    fn saw(&self, method: &str) -> bool {
        self.seen.lock().iter().any(|m| m == method)
    }

    fn task_calls(&self) -> usize {
        self.seen
            .lock()
            .iter()
            .filter(|m| {
                let m = m.to_ascii_lowercase();
                m.starts_with("tasks/") || m == "subscriptions/listen"
            })
            .count()
    }
}

#[async_trait::async_trait]
impl crate::transport::Transport for TaskBackend {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        self.seen.lock().push(method.to_string());
        let result = match method.to_ascii_lowercase().as_str() {
            "tools/call" => json!({
                "task": { "taskId": TASK_A, "status": "working" }
            }),
            "tasks/get" => json!({
                "taskId": TASK_A,
                "status": "completed",
                "result": { "content": [{ "type": "text", "text": SECRET_A }] }
            }),
            _ => json!({}),
        };
        Ok(JsonRpcResponse::success(RequestId::Number(1), result))
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

fn key(name: &str, backend: &str) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(name.as_bytes())),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec![backend.to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
    }
}

/// A gateway with auth on, two non-admin keys both scoped to `shared`, and
/// `shared` served by a [`TaskBackend`].
async fn gateway() -> (Arc<super::AppState>, Arc<TaskBackend>) {
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![
            key(KEY_A, "shared"),
            key(KEY_B, "shared"),
            key(KEY_C, "other"),
        ],
        ..Default::default()
    };
    let (state, _store) = test_router_app_state_with_auth(&auth).await;
    let wire = Arc::new(TaskBackend {
        seen: parking_lot::Mutex::new(Vec::new()),
    });
    let backend = Arc::new(Backend::new(
        "shared",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::clone(&wire) as Arc<dyn crate::transport::Transport>);
    assert!(state.backends.register(backend), "fixture registration");
    (state, wire)
}

async fn send(
    state: &Arc<super::AppState>,
    key: &str,
    method: &str,
    params: Value,
) -> (StatusCode, Value) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(DIRECT)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "id": 77, "method": method, "params": params }).to_string(),
        ))
        .unwrap();
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

/// Caller A creates a backend task on the direct route. The call reaches the
/// backend and returns A's task id; this is the setup both refusal rows share.
async fn caller_a_creates_a_task(state: &Arc<super::AppState>, wire: &TaskBackend) {
    let (status, body) = send(
        state,
        KEY_A,
        "tools/call",
        json!({ "name": "slow", "arguments": {}, "task": { "ttl": 60000 } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        wire.saw("tools/call"),
        "setup: A's call never reached the backend"
    );
    assert_eq!(body["result"]["task"]["taskId"], TASK_A, "setup: {body}");
}

/// B's refusal: -32601 on B's own id, no A data, and zero `tasks/*` calls on the wire.
fn assert_refused_without_forward(
    method: &str,
    status: StatusCode,
    body: &Value,
    wire: &TaskBackend,
) {
    assert_eq!(
        wire.task_calls(),
        0,
        "{method} on the direct route reached the backend: {:?}",
        wire.seen.lock()
    );
    assert_eq!(body["error"]["code"], -32601, "{method}: {body}");
    assert_eq!(
        body["id"], 77,
        "{method} refusal must carry the caller's id: {body}"
    );
    assert!(
        !body.to_string().contains(SECRET_A),
        "{method} disclosed A's result: {body}"
    );
    assert_eq!(status, StatusCode::OK, "{method}: {body}");
}

#[tokio::test]
async fn caller_b_tasks_get_for_a_task_never_reaches_backend() {
    let (state, wire) = gateway().await;
    caller_a_creates_a_task(&state, &wire).await;

    let (status, body) = send(&state, KEY_B, "tasks/get", json!({ "taskId": TASK_A })).await;

    assert_refused_without_forward("tasks/get", status, &body, &wire);
}

#[tokio::test]
async fn caller_b_tasks_cancel_for_a_task_never_reaches_backend() {
    let (state, wire) = gateway().await;
    caller_a_creates_a_task(&state, &wire).await;

    let (status, body) = send(&state, KEY_B, "tasks/cancel", json!({ "taskId": TASK_A })).await;

    assert_refused_without_forward("tasks/cancel", status, &body, &wire);
}

/// Every `tasks/*` method is refused, in any letter case: a backend that
/// matches method names loosely acts on a case variant as the real method.
#[tokio::test]
async fn every_task_method_and_case_variant_is_refused() {
    for method in [
        "tasks/update",
        "tasks/list",
        "Tasks/Get",
        "TASKS/CANCEL",
        "Tasks/FutureMethod",
    ] {
        let (state, wire) = gateway().await;
        let (status, body) = send(&state, KEY_B, method, json!({ "taskId": TASK_A })).await;
        assert_refused_without_forward(method, status, &body, &wire);
    }
}

/// Positive control: without it, a route that forwards nothing passes every
/// refusal row above.
#[tokio::test]
async fn ordinary_methods_still_forward() {
    for (method, params) in [
        ("tools/call", json!({ "name": "slow", "arguments": {} })),
        (
            "tools/call",
            json!({ "name": "slow", "arguments": {}, "task": { "ttl": 60000 } }),
        ),
        ("resources/list", json!({})),
        ("subscriptions/listen", json!({})),
    ] {
        let (state, wire) = gateway().await;
        let (status, body) = send(&state, KEY_B, method, params).await;
        assert_eq!(status, StatusCode::OK, "{method}: {body}");
        assert!(body.get("error").is_none(), "{method} must succeed: {body}");
        assert!(wire.saw(method), "{method} no longer reaches the backend");
    }
}

/// `subscriptions/listen` naming task ids is task access too: on `/mcp` it is
/// owner-checked, so on this route it is refused like `tasks/*`.
#[tokio::test]
async fn caller_b_task_subscription_never_reaches_backend() {
    let (state, wire) = gateway().await;
    caller_a_creates_a_task(&state, &wire).await;

    for (method, params) in [
        ("subscriptions/listen", json!({ "taskIds": [TASK_A] })),
        ("Subscriptions/Listen", json!({ "taskIds": [TASK_A] })),
        ("subscriptions/listen", json!({ "taskIds": [] })),
        ("subscriptions/listen", json!({ "taskIds": null })),
    ] {
        let (status, body) = send(&state, KEY_B, method, params).await;
        assert_refused_without_forward(method, status, &body, &wire);
    }
}

/// The refusal sits after the backend scope check, so a caller not allowed on
/// the backend still gets the same 403 as for any other method.
#[tokio::test]
async fn out_of_scope_caller_still_gets_403_for_task_methods() {
    let (state, wire) = gateway().await;

    let (status, body) = send(&state, KEY_C, "tasks/get", json!({ "taskId": TASK_A })).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], -32003, "{body}");
    assert_eq!(wire.task_calls(), 0, "{:?}", wire.seen.lock());
}
