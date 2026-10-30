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
use super::ui_tool_call_cell_tests::assert_refused_delivery;
use crate::backend::Backend;
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig};
use crate::gateway::router::{AppState, create_router};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

const ROUTE: &str = "/ui/api/tools/call";
pub(super) const ADMIN: &str = "k-admin";
const USER: &str = "k-user";
/// An admin key denied `write` by policy.
const ADMIN_DENIED: &str = "k-admin-deny";
pub(super) const SERVER: &str = "alpha";

/// A backend whose `tools/list` declares `read`, `fail` and `iserr`
/// read-only and leaves `write` and `get_x` undeclared, counting every call.
pub(super) struct Stub {
    pub(super) calls: Arc<AtomicUsize>,
    /// Declare `read` read-only (false: a replacement that does not).
    pub(super) declares_read: bool,
    /// `tools/list` waits for this, when set: a cold catalogue is filled
    /// before the gate, so a test holds a call there for as long as it likes.
    pub(super) list_gate: Option<Arc<tokio::sync::Notify>>,
}

#[async_trait::async_trait]
impl Transport for Stub {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            if let Some(gate) = &self.list_gate {
                gate.notified().await;
            }
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
                    tool("ask", &ro),
                    tool("flaky", &ro),
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
            // A tool that stops to ask the user a question (elicitation).
            "ask" => Ok(JsonRpcResponse::success(
                id,
                json!({
                    "resultType": "input_required",
                    "inputRequests": {"k1": {
                        "method": "elicitation/create",
                        "params": {"message": "Which account?", "requestedSchema": {"type": "object"}},
                    }},
                    "requestState": "backend-state-1",
                }),
            )),
            "slow" => {
                tokio::time::sleep(Duration::from_millis(400)).await;
                Ok(JsonRpcResponse::success(
                    id,
                    json!({"content": [{"type": "text", "text": "late"}], "isError": false}),
                ))
            }
            // Times out once (the request may have reached it), then cannot be
            // reached: a retry that ends in a connect failure.
            "flaky" if self.calls.load(Ordering::SeqCst) == 1 => {
                Err(crate::Error::BackendTimeout("stub timed out".into()))
            }
            "flaky" => Err(crate::Error::TransportConnect("stub unreachable".into())),
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

pub(super) struct Fx {
    pub(super) state: Arc<AppState>,
    pub(super) calls: Arc<AtomicUsize>,
    audit_path: std::path::PathBuf,
    _audit: tempfile::TempDir,
    _store: crate::gateway::router::tests::FixtureDir,
}

/// A backend `alpha` answered by [`Stub`], its tool list filled, and both
/// audit logs on.
pub(super) async fn fixture() -> Fx {
    fixture_with(Setup::Plain).await
}

/// What the fixture's `MetaMcp` has on beyond the audit logs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Setup {
    Plain,
    /// The response cache, as a server builds it.
    Cached,
    /// Message signing that requires a nonce on every call.
    SignedNonce,
    /// Caller identity from a trusted proxy at [`PROXY`].
    TrustedProxy,
}

/// The trusted proxy the `TrustedProxy` rows' requests arrive from.
pub(super) const PROXY: std::net::SocketAddr = std::net::SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 7)),
    40_000,
);

/// [`fixture`] with the response cache on, as a server builds it.
async fn fixture_cached() -> Fx {
    fixture_with(Setup::Cached).await
}

pub(super) async fn fixture_with(setup: Setup) -> Fx {
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![
            key(ADMIN, true),
            key(USER, false),
            ApiKeyConfig {
                denied_tools: Some(vec!["write".to_string()]),
                ..key(ADMIN_DENIED, true)
            },
        ],
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
    if setup == Setup::TrustedProxy {
        meta = meta.with_caller_identity(crate::security::caller_identity::CallerIdentityConfig {
            mode: crate::security::caller_identity::CallerIdentityMode::TrustedProxy,
            trusted_proxies: vec![PROXY.ip()],
            authority: "corp-sso".to_string(),
            ..Default::default()
        });
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
        list_gate: None,
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

pub(super) fn sent(fx: &Fx) -> usize {
    fx.calls.load(Ordering::SeqCst)
}

pub(super) fn records(fx: &Fx) -> Vec<Value> {
    std::fs::read_to_string(&fx.audit_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// The route's `admin_action` records.
pub(super) fn admin_actions(fx: &Fx) -> Vec<Value> {
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
    // On a refusal, the audit records name the gate that refused.
    assert_eq!(status, StatusCode::OK, "{body} {:#?}", records(&fx));
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
/// `confirm_write` and never sent; with it, it runs once.
#[tokio::test]
async fn t4_an_undeclared_tool_asks_for_confirm_write() {
    let fx = fixture().await;
    let (status, body) = post(&fx, ADMIN, call("write", false)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["disposition"], "not_run", "{body}");
    assert_eq!(sent(&fx), 0, "nothing reached the backend");
    assert_refused_delivery(&fx);
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

/// T7 (API12.2): the `admin_action` record names `ui:key:<name>` and the
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

/// T9 (API12.3): a non-admin key is refused 403 and nothing is sent, and the
/// refusal is still written as an `admin_action` (not run) before it is answered.
/// Mutant: the guard's refusal answered straight back, skipping `finish`.
#[tokio::test]
async fn t9_a_non_admin_is_refused_before_anything_runs() {
    let fx = fixture().await;
    let (status, _) = post(&fx, USER, call("read", false)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(sent(&fx), 0);
    let actions = admin_actions(&fx);
    assert_eq!(actions.len(), 1, "{actions:?}");
    assert_eq!(actions[0]["disposition"], "not_run", "{}", actions[0]);
}

/// T10: a server that is not registered is refused as a denied tool is,
/// not run and nothing sent: its failure comes after the send mark, and the
/// gateway's own pre-dispatch judgement clears it. /mcp answers a server it
/// does not have, a missing tool and a denied one alike (T28), so the route
/// does too.
/// Mutant: the send mark kept on a pre-dispatch failure (then "may have run").
#[tokio::test]
async fn t10_no_such_server_is_not_run() {
    let fx = fixture().await;
    let ghost = json!({"server": "ghost", "tool": "read", "arguments": {}, "confirm_write": true});
    let (status, body) = post(&fx, ADMIN_DENIED, ghost).await;
    assert_eq!(body["disposition"], "not_run", "{body} {:#?}", records(&fx));
    let (denied_status, denied) = post(&fx, ADMIN_DENIED, call("write", true)).await;
    assert_eq!(
        (status, &body),
        (denied_status, &denied),
        "as a denied tool"
    );
    assert!(status.is_client_error(), "{status}");
    assert_eq!(sent(&fx), 0);
}

/// T28 (lead): a tool missing from a registered server and a tool the
/// caller's policy denies are answered alike on /mcp (names aside), and
/// alike by the route: the route names no more than /mcp does.
#[tokio::test]
async fn t28_a_missing_tool_and_a_denied_one_answer_alike() {
    let fx = fixture().await;
    let mcp = |tool: &'static str| {
        let fx = &fx;
        async move {
            let raw = post_mcp(fx, ADMIN_DENIED, invoke(tool), None).await;
            String::from_utf8_lossy(&raw).replace(tool, "<tool>")
        }
    };
    let (denied, missing) = (mcp("write").await, mcp("missing").await);
    let mask = |s: &str| {
        let mut v: Value = serde_json::from_str(s).unwrap_or(Value::Null);
        if let Some(o) = v.pointer_mut("/result").and_then(Value::as_object_mut) {
            o.remove("trace_id");
        }
        v
    };
    assert_eq!(mask(&denied), mask(&missing), "/mcp: {denied} vs {missing}");
    let (s1, b1) = post(&fx, ADMIN_DENIED, call("write", true)).await;
    let (s2, b2) = post(&fx, ADMIN_DENIED, call("missing", true)).await;
    assert_eq!((s1, &b1), (s2, &b2), "the route");
    assert!(s1.is_client_error(), "{s1} {b1}");
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

/// T17: a 409 and a 404 each still write an `admin_action` naming server
/// and tool.
#[tokio::test]
async fn t17_refusals_are_audited_with_their_target() {
    let fx = fixture().await;
    let (status, _) = post(&fx, ADMIN, call("write", false)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = post(&fx, ADMIN, call("missing", true)).await;
    // Answered as a forbidden tool is (T28).
    assert_eq!(status, StatusCode::FORBIDDEN, "{:#?}", records(&fx));
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

/// POST `params` as a modern `tools/call` to `/mcp` as `key`, inside `scope`
/// when given; the raw answer bytes.
pub(super) async fn post_mcp(
    fx: &Fx,
    key: &str,
    params: Value,
    scope: Option<Arc<crate::gateway::ui_call::UiCall>>,
) -> Vec<u8> {
    let revision = crate::protocol::meta::FIRST_STATELESS_VERSION;
    let mut params = params;
    params["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!(revision);
    if params["_meta"]
        .get("io.modelcontextprotocol/clientCapabilities")
        .is_none()
    {
        params["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({});
    }
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

pub(super) fn invoke(tool: &str) -> Value {
    json!({"name": "gateway_invoke", "arguments": {"server": SERVER, "tool": tool, "arguments": {}}})
}

/// T23: a UI call bypasses the response cache: two calls of a declared
/// read-only tool reach the backend twice.
/// Mutant: the cache bypass removed.
#[tokio::test]
async fn t23_a_ui_call_is_never_served_from_the_cache() {
    let fx = fixture_cached().await;
    // Control: the cache is on, so two /mcp calls send once.
    let mut answers = Vec::new();
    for _ in 0..2 {
        let answer = post_mcp(&fx, ADMIN, invoke("read"), None).await;
        answers.push(String::from_utf8_lossy(&answer).into_owned());
    }
    assert_eq!(
        sent(&fx),
        1,
        "the premise: /mcp is served from the cache: {answers:#?}"
    );
    for _ in 0..2 {
        let (status, body) = post(&fx, ADMIN, call("read", false)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    assert_eq!(sent(&fx), 3, "both UI calls reached the backend");
}

/// T12: past the deadline the route answers 504 "may have run"; the sent
/// call finishes, and its invocation record and a completion `admin_action`
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
    assert_eq!(
        completion["outcome"], "ok",
        "how the call ended: {completion}"
    );
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
/// the backend sees nothing for it and an `admin_action` records the refusal.
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

/// T27 (lead): a tool that stops to ask a follow-up question cannot finish
/// from the web UI, which declares no client capabilities: dispatch refuses
/// the undeclared round after the send, so the route answers a 5xx, may have
/// run, never 200 and never a 4xx.
/// Mutant: a failure after the send read as not run.
#[tokio::test]
async fn t27_a_tool_that_asks_a_question_answers_may_have_run() {
    let fx = fixture().await;
    let (status, body) = post(&fx, ADMIN, call("ask", false)).await;
    assert!(status.is_server_error(), "{status} {body}");
    assert_eq!(body["disposition"], "may_have_run", "{body}");
    assert_eq!(sent(&fx), 1, "the call was sent");
    assert!(!body.to_string().contains("Which account"), "{body}");
}

/// T30 (code review): a retry that ends in a connect failure after an
/// attempt that timed out may have run: the first attempt may have reached
/// the backend, so the route answers a 5xx, never "not run".
/// Mutant: the send mark cleared on any error the gateway calls pre-dispatch.
#[tokio::test]
async fn t30_a_retry_ending_unreachable_may_have_run() {
    let fx = fixture().await;
    let (status, body) = post(&fx, ADMIN, call("flaky", false)).await;
    assert!(
        sent(&fx) >= 2,
        "the premise: it was retried ({})",
        sent(&fx)
    );
    assert!(status.is_server_error(), "{status} {body}");
    assert_eq!(body["disposition"], "may_have_run", "{body}");
}
/// T7b (code review): a dashboard-session caller, whose principal reaches
/// the gate as the cookie names it: the call runs, its `admin_action` names
/// `ui:session:`, and its invocation names the same principal.
#[tokio::test]
async fn t7b_a_dashboard_session_runs_and_is_audited_as_itself() {
    use crate::gateway::auth::{Now, SESSION_COOKIE, SessionLimits};
    let fx = fixture().await;
    let limits = SessionLimits::from(&fx.state.live_config.get().auth.dashboard_session);
    let handle = fx
        .state
        .dashboard_bootstrap
        .issue_session_at(Now::read(), &limits);
    let request = Request::builder()
        .method("POST")
        .uri(ROUTE)
        .header("cookie", format!("{SESSION_COOKIE}={handle}"))
        .header("content-type", "application/json")
        .body(Body::from(call("read", false).to_string()))
        .expect("request");
    let response = create_router(Arc::clone(&fx.state))
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_eq!(status, StatusCode::OK, "{body} {:#?}", records(&fx));
    let receipt = body["receipt"].as_str().expect("a receipt").to_owned();
    let action = admin_actions(&fx).pop().expect("the admin_action");
    assert!(
        action["via"]
            .as_str()
            .is_some_and(|v| v.starts_with("ui:session:")),
        "{action}"
    );
    let invocation = records(&fx)
        .into_iter()
        .find(|r| r["trace_id"] == receipt.as_str() && r["event"] != "admin_action")
        .expect("the invocation's record");
    assert_eq!(
        invocation["who"]["principal"], action["who"]["principal"],
        "{invocation}"
    );
}
