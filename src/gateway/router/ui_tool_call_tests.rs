// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Try a tool from the web UI (U12): `POST /ui/api/tools/call` runs through
//! the one MCP dispatch, asks for `confirm_write` unless the server declared
//! the tool read-only, and answers a status that tells "did not run" (4xx)
//! from "ran" (200) and "may have run" (5xx).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::tests::test_router_app_state_with_auth_and_config;
use crate::backend::Backend;
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig};
use crate::gateway::router::{AppState, create_router};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

const ROUTE: &str = "/ui/api/tools/call";
const ADMIN: &str = "k-admin";
const USER: &str = "k-user";
const SERVER: &str = "alpha";

/// A backend whose `tools/list` declares `read`, `fail` and `iserr`
/// read-only and leaves `write` and `get_x` undeclared, counting every call.
struct Stub {
    calls: Arc<AtomicUsize>,
    /// Declare `read` read-only (false: a replacement that does not).
    declares_read: bool,
}

#[async_trait::async_trait]
impl Transport for Stub {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            let ro = json!({"readOnlyHint": true});
            let read = if self.declares_read {
                ro.clone()
            } else {
                json!({})
            };
            let tool = |name: &str, annotations: &Value| json!({"name": name, "inputSchema": {"type": "object"}, "annotations": annotations});
            return Ok(JsonRpcResponse::success(
                id,
                json!({"tools": [
                    tool("read", &read),
                    tool("fail", &ro),
                    tool("iserr", &ro),
                    tool("slow", &ro),
                    tool("write", &json!({})),
                    tool("get_x", &json!({})),
                ]}),
            ));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        let name = params
            .as_ref()
            .and_then(|p| p["name"].as_str())
            .unwrap_or_default()
            .to_owned();
        match name.as_str() {
            "slow" => {
                tokio::time::sleep(Duration::from_millis(400)).await;
                Ok(JsonRpcResponse::success(
                    id,
                    json!({"content": [{"type": "text", "text": "late"}], "isError": false}),
                ))
            }
            "fail" => Err(crate::Error::BackendTimeout("stub timed out".into())),
            "iserr" => Ok(JsonRpcResponse::success(
                id,
                json!({"content": [{"type": "text", "text": "no"}], "isError": true}),
            )),
            _ => Ok(JsonRpcResponse::success(
                id,
                json!({"content": [{"type": "text", "text": "done"}], "isError": false}),
            )),
        }
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

fn key(name: &str, admin: bool) -> ApiKeyConfig {
    ApiKeyConfig {
        key_sha256: Some(crate::config::api_key_digest_spec(name.as_bytes())),
        name: name.to_string(),
        backends: vec!["*".to_string()],
        admin,
        ..Default::default()
    }
}

struct Fx {
    state: Arc<AppState>,
    calls: Arc<AtomicUsize>,
    audit_path: std::path::PathBuf,
    _audit: tempfile::TempDir,
    _store: tempfile::TempDir,
}

/// A backend `alpha` answered by [`Stub`], its tool list filled, and both
/// audit logs on.
async fn fixture() -> Fx {
    fixture_with(Setup::Plain).await
}

/// What the fixture's `MetaMcp` has on beyond the audit logs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Setup {
    Plain,
    /// The response cache, as a server builds it.
    Cached,
    /// Message signing that requires a nonce on every call.
    SignedNonce,
}

/// [`fixture`] with the response cache on, as a server builds it.
async fn fixture_cached() -> Fx {
    fixture_with(Setup::Cached).await
}

async fn fixture_with(setup: Setup) -> Fx {
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![key(ADMIN, true), key(USER, false)],
        ..Default::default()
    };
    let (mut state, store) =
        test_router_app_state_with_auth_and_config(&auth, crate::config::Config::default()).await;
    let audit = tempfile::tempdir().expect("a log directory");
    let audit_path = audit.path().join("audit.jsonl");
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: audit_path.to_string_lossy().into_owned(),
                key_id: "8865".to_string(),
                ..crate::security::transparency_log::TransparencyLogConfig::default()
            },
        ))
        .expect("open log"),
    );
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    let backends = Arc::clone(&state_mut.backends);
    let mut meta = if setup == Setup::Cached {
        crate::gateway::MetaMcp::with_features(
            backends,
            Some(Arc::new(crate::cache::ResponseCache::new())),
            None,
            None,
            Duration::from_secs(60),
        )
    } else {
        crate::gateway::MetaMcp::new(backends)
    };
    if setup == Setup::SignedNonce {
        meta.enable_message_signing(
            crate::security::message_signing::MessageSigner::new(
                b"ui-tool-call-test-signing-key-0123456789".to_vec(),
                None,
                "ui".into(),
            ),
            Duration::from_secs(300),
            true,
        );
    }
    meta.enable_transparency_log(Arc::clone(&log));
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(log);
    let calls = Arc::new(AtomicUsize::new(0));
    register(&state, &calls, true).await;
    Fx {
        state,
        calls,
        audit_path,
        _audit: audit,
        _store: store,
    }
}

/// Register `alpha` (replacing any earlier one) answered by a [`Stub`]
/// counting into `calls`, and fill its tool list.
async fn register(state: &Arc<AppState>, calls: &Arc<AtomicUsize>, declares_read: bool) {
    register_as(state, calls, declares_read, BackendConfig::default()).await;
}

/// [`register`] under `config` (its transport kind, say).
async fn register_as(
    state: &Arc<AppState>,
    calls: &Arc<AtomicUsize>,
    declares_read: bool,
    config: BackendConfig,
) {
    let backend = Arc::new(Backend::new(
        SERVER,
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Stub {
        calls: Arc::clone(calls),
        declares_read,
    }));
    assert!(
        state.backends.register(Arc::clone(&backend)),
        "registration"
    );
    backend
        .get_tools_shared()
        .await
        .expect("the tool list fills");
}

/// POST `body` to the route as `key`; the status and the JSON answer.
async fn post(fx: &Fx, key: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(ROUTE)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let response = create_router(Arc::clone(&fx.state))
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn call(tool: &str, confirm_write: bool) -> Value {
    json!({"server": SERVER, "tool": tool, "arguments": {}, "confirm_write": confirm_write})
}

fn sent(fx: &Fx) -> usize {
    fx.calls.load(Ordering::SeqCst)
}

fn records(fx: &Fx) -> Vec<Value> {
    std::fs::read_to_string(&fx.audit_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// The route's `admin_action` records.
fn admin_actions(fx: &Fx) -> Vec<Value> {
    records(fx)
        .into_iter()
        .filter(|r| r["event"] == "admin_action" && r.to_string().contains(ROUTE))
        .collect()
}

/// T1 (API12.1): a declared read-only tool runs through dispatch: 200, the
/// backend's result, a latency, and a receipt that is the invocation's trace.
#[tokio::test]
async fn t1_a_declared_read_runs_and_returns_its_receipt() {
    let fx = fixture().await;
    let (status, body) = post(&fx, ADMIN, call("read", false)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(sent(&fx), 1);
    assert_eq!(body["disposition"], "ran", "{body}");
    assert_eq!(body["is_error"], false, "{body}");
    assert_eq!(body["result"]["content"][0]["text"], "done", "{body}");
    assert!(body["latency_ms"].is_u64(), "{body}");
    let receipt = body["receipt"].as_str().expect("a receipt");
    assert!(
        records(&fx)
            .iter()
            .any(|r| r["trace_id"] == receipt && r["event"] != "admin_action"),
        "the receipt names the invocation's records"
    );
}

/// T4 (API12.2): a tool with no readOnlyHint is refused 409 without
/// confirm_write and never sent; with it, it runs once.
#[tokio::test]
async fn t4_an_undeclared_tool_asks_for_confirm_write() {
    let fx = fixture().await;
    let (status, body) = post(&fx, ADMIN, call("write", false)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["disposition"], "not_run", "{body}");
    assert_eq!(sent(&fx), 0, "nothing reached the backend");
    let (status, body) = post(&fx, ADMIN, call("write", true)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(sent(&fx), 1);
}

/// T5 (API12.2): a `get_*` name with no declared hint still asks.
#[tokio::test]
async fn t5_an_inferred_read_still_asks() {
    let fx = fixture().await;
    let (status, _) = post(&fx, ADMIN, call("get_x", false)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(sent(&fx), 0);
}

/// T6b (API12.2): `alpha` replaced by an instance that does not declare
/// `read`: the declaration judged is the replacement's, so `read` asks.
#[tokio::test]
async fn t6b_a_replaced_backend_is_judged_by_its_own_list() {
    let fx = fixture().await;
    register(&fx.state, &fx.calls, false).await;
    let (status, _) = post(&fx, ADMIN, call("read", false)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(sent(&fx), 0);
}

/// T7 (API12.2): the admin_action record names `ui:key:<name>` and the
/// receipt; the invocation under that trace names the same principal, not
/// a `ui:` one.
#[tokio::test]
async fn t7_audited_as_ui_principal_and_linked_to_the_invocation() {
    let fx = fixture().await;
    let (status, body) = post(&fx, ADMIN, call("read", false)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let receipt = body["receipt"].as_str().expect("a receipt").to_owned();
    let actions = admin_actions(&fx);
    assert_eq!(actions.len(), 1, "{actions:?}");
    let action = &actions[0];
    assert_eq!(action["via"], format!("ui:key:{ADMIN}"), "{action}");
    assert_eq!(action["invocation_trace"], receipt.as_str(), "{action}");
    assert_eq!(action["server"], SERVER, "{action}");
    assert_eq!(action["tool"], "read", "{action}");
    let invocation: Vec<Value> = records(&fx)
        .into_iter()
        .filter(|r| r["trace_id"] == receipt.as_str() && r["event"] != "admin_action")
        .collect();
    assert!(!invocation.is_empty(), "the invocation's records");
    for record in &invocation {
        assert_eq!(
            record["who"]["principal"], action["who"]["principal"],
            "{record}"
        );
        assert!(!record.to_string().contains("ui:key:"), "{record}");
    }
}

/// T9 (API12.3): a non-admin key is refused 403 and nothing is sent.
#[tokio::test]
async fn t9_a_non_admin_is_refused_before_anything_runs() {
    let fx = fixture().await;
    let (status, _) = post(&fx, USER, call("read", false)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(sent(&fx), 0);
}

/// T10: no such server, no such tool: 404, nothing sent.
#[tokio::test]
async fn t10_no_such_server_or_tool_is_404() {
    let fx = fixture().await;
    let ghost = json!({"server": "ghost", "tool": "read", "arguments": {}, "confirm_write": true});
    let (status, body) = post(&fx, ADMIN, ghost).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = post(&fx, ADMIN, call("missing", true)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["disposition"], "not_run", "{body}");
    assert_eq!(sent(&fx), 0);
}

/// T11: the tool's own `isError` answer is a result: 200, `is_error: true`.
#[tokio::test]
async fn t11_a_tool_error_is_a_result() {
    let fx = fixture().await;
    let (status, body) = post(&fx, ADMIN, call("iserr", false)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["is_error"], true, "{body}");
    assert_eq!(body["disposition"], "ran", "{body}");
}

/// T15: a backend timeout after the send is "may have run" (5xx), never a
/// 4xx: -32000 is also the rate refusal's code, so no code is read.
#[tokio::test]
async fn t15_a_failure_after_the_send_is_never_4xx() {
    let fx = fixture().await;
    let (status, body) = post(&fx, ADMIN, call("fail", false)).await;
    assert!(status.is_server_error(), "{status} {body}");
    assert_eq!(body["disposition"], "may_have_run", "{body}");
    assert!(sent(&fx) >= 1, "the call was sent");
}

/// T17: a 409 and a 404 each still write an admin_action naming server
/// and tool.
#[tokio::test]
async fn t17_refusals_are_audited_with_their_target() {
    let fx = fixture().await;
    let (status, _) = post(&fx, ADMIN, call("write", false)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = post(&fx, ADMIN, call("missing", true)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let actions = admin_actions(&fx);
    assert_eq!(actions.len(), 2, "{actions:?}");
    assert_eq!(actions[0]["tool"], "write", "{}", actions[0]);
    assert_eq!(actions[0]["confirm_write"], false, "{}", actions[0]);
    assert_eq!(actions[0]["disposition"], "not_run", "{}", actions[0]);
    assert_eq!(actions[1]["tool"], "missing", "{}", actions[1]);
    assert_eq!(actions[1]["server"], SERVER, "{}", actions[1]);
}

/// C1: a body that is not the request shape answers 400 or 422 before
/// anything runs; extra fields are refused, not ignored.
#[tokio::test]
async fn c1_bad_bodies_are_refused_before_dispatch() {
    let fx = fixture().await;
    let (status, _) = post(&fx, ADMIN, json!("not an object")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let mut extra = call("read", false);
    extra["also"] = json!(1);
    let (status, _) = post(&fx, ADMIN, extra).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let mut scalar = call("read", false);
    scalar["arguments"] = json!([1]);
    let (status, _) = post(&fx, ADMIN, scalar).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(sent(&fx), 0);
}

/// `key`'s principal as the auth layer derives it from the secret.
fn principal_of(key: &str) -> String {
    crate::hashing::sha256_hex(key.as_bytes())[..12].to_owned()
}

/// POST `params` as a modern `tools/call` to `/mcp` as `key`, inside `scope`
/// when given; the raw answer bytes.
async fn post_mcp(
    fx: &Fx,
    key: &str,
    params: Value,
    scope: Option<Arc<crate::gateway::ui_call::UiCall>>,
) -> Vec<u8> {
    let revision = crate::protocol::meta::FIRST_STATELESS_VERSION;
    let mut params = params;
    params["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!(revision);
    let name = params["name"].as_str().unwrap_or_default().to_owned();
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .header("mcp-protocol-version", revision)
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .body(Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
                .to_string(),
        ))
        .expect("request");
    let router = create_router(Arc::clone(&fx.state));
    let response = match scope {
        Some(call) => call.scope(router.oneshot(request)).await,
        None => router.oneshot(request).await,
    }
    .expect("response");
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec()
}

fn invoke(tool: &str) -> Value {
    json!({"name": "gateway_invoke", "arguments": {"server": SERVER, "tool": tool, "arguments": {}}})
}

fn ui_call(
    tool: &str,
    principal: &str,
    confirm: crate::gateway::ui_call::Confirm,
) -> Arc<crate::gateway::ui_call::UiCall> {
    crate::gateway::ui_call::UiCall::new(SERVER, tool, principal, confirm)
}

/// T21: a UI call whose dispatch runs as another principal than the admin
/// the route checked is refused before the send.
/// Mutant: the principal comparison removed.
#[tokio::test]
async fn t21_a_principal_mismatch_is_refused_before_the_send() {
    let fx = fixture().await;
    let call = ui_call(
        "read",
        "someone-else",
        crate::gateway::ui_call::Confirm::Confirmed,
    );
    let body = post_mcp(&fx, ADMIN, invoke("read"), Some(Arc::clone(&call))).await;
    let body: Value = serde_json::from_slice(&body).expect("json");
    assert!(body.get("error").is_some(), "{body}");
    assert_eq!(sent(&fx), 0);
    assert!(!call.outcome().dispatched);
}

/// T22: a UI call confirmed for one tool cannot send another.
/// Mutant: the target comparison removed.
#[tokio::test]
async fn t22_a_call_for_another_target_is_refused() {
    let fx = fixture().await;
    let principal = principal_of(ADMIN);
    // Control: the matching target is sent.
    let ok = ui_call(
        "write",
        &principal,
        crate::gateway::ui_call::Confirm::Confirmed,
    );
    let _ = post_mcp(&fx, ADMIN, invoke("write"), Some(Arc::clone(&ok))).await;
    assert_eq!(sent(&fx), 1, "the premise: a matching call runs");
    let other = ui_call(
        "read",
        &principal,
        crate::gateway::ui_call::Confirm::Confirmed,
    );
    let body = post_mcp(&fx, ADMIN, invoke("write"), Some(Arc::clone(&other))).await;
    let body: Value = serde_json::from_slice(&body).expect("json");
    assert!(body.get("error").is_some(), "{body}");
    assert_eq!(sent(&fx), 1, "the foreign target was never sent");
}

/// T18: a task-augmented call under a UI call is refused before any task
/// exists: its worker would run outside the UI call.
/// Mutant: the task refusal removed.
#[tokio::test]
async fn t18_a_ui_call_never_runs_as_a_task() {
    let fx = fixture().await;
    let call = ui_call(
        "read",
        &principal_of(ADMIN),
        crate::gateway::ui_call::Confirm::Confirmed,
    );
    let mut params = invoke("read");
    params["task"] = json!({});
    params["_meta"] = json!({(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): "t18"});
    let body = post_mcp(&fx, ADMIN, params, Some(call)).await;
    let body: Value = serde_json::from_slice(&body).expect("json");
    assert!(body.get("error").is_some(), "{body}");
    // No task was made, so no worker exists to send it later.
    assert!(body.pointer("/result/taskId").is_none(), "{body}");
    assert_eq!(sent(&fx), 0);
}

/// T23: a UI call bypasses the response cache: two calls of a declared
/// read-only tool reach the backend twice.
/// Mutant: the cache bypass removed.
#[tokio::test]
async fn t23_a_ui_call_is_never_served_from_the_cache() {
    let fx = fixture_cached().await;
    // Control: the cache is on, so two /mcp calls send once.
    for _ in 0..2 {
        let _ = post_mcp(&fx, ADMIN, invoke("read"), None).await;
    }
    assert_eq!(sent(&fx), 1, "the premise: /mcp is served from the cache");
    for _ in 0..2 {
        let (status, body) = post(&fx, ADMIN, call("read", false)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    assert_eq!(sent(&fx), 3, "both UI calls reached the backend");
}

/// T12: past the deadline the route answers 504 "may have run"; the sent
/// call finishes, and its invocation record and a completion admin_action
/// naming its trace still appear.
/// Mutant: the deadline not enforced (the timeout removed).
#[tokio::test]
async fn t12_a_deadline_answers_504_and_the_records_still_land() {
    let fx = fixture().await;
    crate::gateway::ui::DEADLINE_FOR_TEST.with(|d| d.set(Some(Duration::from_millis(100))));
    let (status, body) = post(&fx, ADMIN, call("slow", false)).await;
    crate::gateway::ui::DEADLINE_FOR_TEST.with(|d| d.set(None));
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{body}");
    assert_eq!(body["disposition"], "may_have_run", "{body}");
    // The call runs on past the answer: wait for its completion record.
    let completion = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(found) = admin_actions(&fx)
                .into_iter()
                .find(|a| a["completion"] == true)
            {
                return found;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a completion record");
    assert_eq!(sent(&fx), 1);
    assert_eq!(completion["disposition"], "ran", "{completion}");
    let trace = completion["invocation_trace"].as_str().expect("its trace");
    assert!(
        records(&fx)
            .iter()
            .any(|r| r["trace_id"] == trace && r["event"] != "admin_action"),
        "the invocation's records landed"
    );
}

/// T19: a server configured over stdio: an undeclared tool asks and is not
/// sent; a declared one runs and records its send and trace.
/// Mutant: the gate reads no UI call (`gate` returns `Ok` at once).
#[tokio::test]
async fn t19_a_stdio_server_is_gated_and_recorded_alike() {
    let fx = fixture().await;
    let stdio = BackendConfig {
        transport: crate::config::TransportConfig::Stdio {
            command: "stub-mcp".to_string(),
            cwd: None,
            protocol_version: None,
        },
        ..BackendConfig::default()
    };
    register_as(&fx.state, &fx.calls, true, stdio).await;
    let (status, _) = post(&fx, ADMIN, call("write", false)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(sent(&fx), 0);
    let (status, body) = post(&fx, ADMIN, call("read", false)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["disposition"], "ran", "{body}");
    assert!(body["receipt"].is_string(), "{body}");
    assert_eq!(sent(&fx), 1);
}

/// A result carrying a credential the response firewall withholds.
#[cfg(feature = "firewall")]
const WITH_SECRET: &str = concat!("token=", "gh", "p_", "0123456789abcdefghij0123456789abcdef");

/// T13b: the /mcp answer for a firewall-withheld result is byte-identical
/// with and without a UI call in scope: the cell never reaches the wire.
/// Mutant: the gate refuses every call in scope (the target check inverted).
#[cfg(feature = "firewall")]
#[tokio::test]
async fn t13b_mcp_bytes_are_unchanged_by_a_ui_call_in_scope() {
    use super::direct_guards_fixture::{Answer, fixture_firewalled_with};
    let fx = fixture_firewalled_with(Answer::Text(WITH_SECRET), None, false).await;
    let send = |scope: Option<Arc<crate::gateway::ui_call::UiCall>>| {
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("authorization", "Bearer k-std")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                    "name": "gateway_invoke",
                    "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
                }})
                .to_string(),
            ))
            .expect("request");
        let router = fx.router.clone();
        async move {
            let response = match scope {
                Some(call) => call.scope(router.oneshot(request)).await,
                None => router.oneshot(request).await,
            }
            .expect("response");
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body")
        }
    };
    let plain = send(None).await;
    let call = crate::gateway::ui_call::UiCall::new(
        "alpha",
        "read",
        &principal_of("k-std"),
        crate::gateway::ui_call::Confirm::Confirmed,
    );
    let scoped = send(Some(Arc::clone(&call))).await;
    let body: Value = serde_json::from_slice(&plain).expect("json");
    assert_eq!(
        body["error"]["message"], "Response blocked by security firewall",
        "the premise: the answer is withheld: {body}"
    );
    assert_eq!(plain, scoped, "the same bytes with a UI call in scope");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 2, "both were sent");
    assert!(call.outcome().dispatched, "the scoped one was recorded");
}

/// Spawns on the path that are not the send: (file, line text, why).
const SPAWN_ALLOWED: &[(&str, &str, &str)] = &[
    (
        "src/gateway/meta_mcp/grant_audit.rs",
        "handle.spawn(async move {",
        "spawn_write: a bounded write of grant records, after the call",
    ),
    (
        "src/gateway/meta_mcp/grant_audit.rs",
        "let flush = tokio::spawn(async move { write_records(&writer, &notes).await });",
        "the slot's record flush, after the call",
    ),
    (
        "src/gateway/meta_mcp/grant_audit.rs",
        "let writer = tokio::spawn(async move {",
        "the record writer for a refused call",
    ),
];

/// T20 (design C0b): a web UI call's cell is a task-local, which does not
/// cross a spawn. Nothing between the MCP handler and the send spawns, so
/// the cell reaches the gate and the send record; a spawn added there fails
/// this row, and whoever adds it must carry the cell across.
#[test]
fn t20_no_spawn_wraps_the_send() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    let handlers = root.join("src/gateway/router/handlers");
    for entry in std::fs::read_dir(&handlers).expect("handlers") {
        let path = entry.expect("entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name == "meta_handler.rs" || name.starts_with("dispatch_") {
            files.push(path);
        }
    }
    let mut dirs = vec![
        root.join("src/gateway/meta_mcp/call_dispatch"),
        root.join("src/gateway/meta_mcp/invoke"),
    ];
    files.push(root.join("src/gateway/meta_mcp/call_dispatch.rs"));
    files.push(root.join("src/gateway/meta_mcp/grant_audit.rs"));
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("a scanned directory") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    let mut found = Vec::new();
    let mut used = vec![false; SPAWN_ALLOWED.len()];
    for path in files {
        let rel = path
            .strip_prefix(root)
            .expect("under the root")
            .to_string_lossy()
            .replace('\\', "/");
        if rel.contains("_tests") || rel.contains("/tests/") || rel.ends_with("fixture.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("readable");
        for (n, line) in text.lines().enumerate() {
            let code = line.trim();
            if code.starts_with("//") {
                continue;
            }
            let spawns = ["tokio::spawn(", "spawn_blocking(", "JoinSet", ".spawn("]
                .iter()
                .any(|p| code.contains(p));
            if !spawns {
                continue;
            }
            match SPAWN_ALLOWED
                .iter()
                .position(|(f, l, _)| *f == rel && code == *l)
            {
                Some(i) => used[i] = true,
                None => found.push(format!("{rel}:{}: {code}", n + 1)),
            }
        }
    }
    assert!(found.is_empty(), "a spawn on the dispatch path: {found:#?}");
    let stale: Vec<_> = SPAWN_ALLOWED
        .iter()
        .zip(&used)
        .filter(|(_, u)| !**u)
        .map(|(r, _)| r.1)
        .collect();
    assert!(
        stale.is_empty(),
        "allowlist rows that match nothing: {stale:?}"
    );
}

fn capability(read_only: bool) -> crate::capability::CapabilityDefinition {
    let yaml = format!(
        r"
name: probe
description: Test capability
metadata:
  read_only: {read_only}
providers:
  primary:
    service: rest
    config:
      base_url: https://example.invalid
      path: /probe
"
    );
    crate::capability::parse_capability(&yaml).expect("capability")
}

/// T24: the capability executor judges the definition it is about to run,
/// so a reload after the dispatch gate cannot run a write unconfirmed.
/// Mutant: the UI arm in the capability executor removed.
#[tokio::test]
async fn t24_a_capability_is_judged_by_the_definition_it_runs() {
    use crate::capability::{CapabilityBackend, CapabilityExecutor};
    use crate::gateway::ui_call::{Confirm, UiCall};
    for (read_only, refused) in [(false, true), (true, false)] {
        let backend = CapabilityBackend::new("caps", Arc::new(CapabilityExecutor::new()));
        backend
            .register_capability(capability(read_only))
            .expect("registered");
        let call = UiCall::new("caps", "probe", "p", Confirm::DeclaredReadOnlyOnly);
        // The REST provider is unreachable, so a call the gate lets through
        // fails later, for another reason.
        let _ = call.scope(backend.call_tool("probe", json!({}))).await;
        assert_eq!(
            call.outcome().confirm_refused,
            refused,
            "read_only: {read_only}"
        );
    }
}

/// T25 (lead): under signing that requires a nonce, the route mints none
/// for the caller: 403 `signing_required`, nothing sent, the refusal audited.
/// Mutant: the up-front signing check removed (dispatch then refuses with
/// the no-such-tool code, and the route answers 404).
#[tokio::test]
async fn t25_required_signing_is_refused_up_front() {
    let fx = fixture_with(Setup::SignedNonce).await;
    let (status, body) = post(&fx, ADMIN, call("read", false)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "signing_required", "{body}");
    assert_eq!(body["disposition"], "not_run", "{body}");
    assert_eq!(sent(&fx), 0);
    let actions = admin_actions(&fx);
    assert_eq!(actions.len(), 1, "{actions:?}");
    assert_eq!(actions[0]["tool"], "read", "{}", actions[0]);
}

/// T26 (lead): with the pool's calls all held, the next answers 403 `busy`;
/// the backend sees nothing for it and an admin_action records the refusal.
/// Mutant: the pool permit not taken.
#[tokio::test]
async fn t26_a_full_pool_answers_busy() {
    let fx = fixture().await;
    let held: Vec<_> = (0..crate::gateway::ui_call::MAX_UI_CALLS)
        .map(|_| {
            Arc::clone(fx.state.meta_mcp.ui_call_permits())
                .try_acquire_owned()
                .expect("a free permit")
        })
        .collect();
    let (status, body) = post(&fx, ADMIN, call("read", false)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "busy", "{body}");
    assert_eq!(body["disposition"], "not_run", "{body}");
    assert_eq!(sent(&fx), 0);
    let actions = admin_actions(&fx);
    assert_eq!(actions.len(), 1, "{actions:?}");
    assert_eq!(actions[0]["disposition"], "not_run", "{}", actions[0]);
    drop(held);
    let (status, _) = post(&fx, ADMIN, call("read", false)).await;
    assert_eq!(status, StatusCode::OK, "a freed pool runs the call");
}
