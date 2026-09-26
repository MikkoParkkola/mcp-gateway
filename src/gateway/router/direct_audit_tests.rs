// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D2 (MIK-7570.AUDIT.2): the direct route `POST /mcp/{name}` writes the same
//! invocation record as the meta route, refusals included.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use crate::backend::Backend;
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext, anonymous_caller};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::TransparencyLogger;
use crate::security::audit::AuditFailurePolicy;
use crate::security::transparency_log::TransparencyLogConfig;
use crate::transport::Transport;

/// A backend that answers `tools/list` with its one tool `t` and anything
/// else with a text result, or with a JSON-RPC error when `error` is set.
struct Scripted {
    calls: Arc<AtomicUsize>,
    error: Option<i32>,
}

#[async_trait::async_trait]
impl Transport for Scripted {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        // F13: a cold `tools/call` lists the backend first. The list names the
        // tool the rows call, and it is not a call, so `calls` skips it.
        if method == "tools/list" {
            let tool = json!({"name": "t", "inputSchema": {"type": "object"}});
            return Ok(JsonRpcResponse::success(id, json!({ "tools": [tool] })));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(match (method, self.error) {
            (_, Some(code)) => JsonRpcResponse::error(Some(id), code, "backend says no"),
            _ => JsonRpcResponse::success(
                id,
                json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
            ),
        })
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

struct Fixture {
    state: Arc<super::AppState>,
    router: axum::Router,
    log: Arc<TransparencyLogger>,
    path: std::path::PathBuf,
    calls: Arc<AtomicUsize>,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

/// Knobs a cell varies; everything else is the plain auth-off gateway.
#[derive(Default)]
struct Setup {
    auth: Option<AuthConfig>,
    fail_closed: bool,
    backend_error: Option<i32>,
    agent_identity: Option<crate::config::AgentIdentityConfig>,
}

/// Backends `alpha` and `beta`, one logger shared by both routes.
async fn fixture(setup: Setup) -> Fixture {
    let audit = tempfile::tempdir().unwrap();
    let path = audit.path().join("audit.jsonl");
    let policy = if setup.fail_closed {
        AuditFailurePolicy::FailClosed
    } else {
        AuditFailurePolicy::BestEffort
    };
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: path.to_string_lossy().into_owned(),
            key_id: "d2".to_string(),
            shared_secret: String::new(),
        }))
        .expect("open log")
        .with_failure_policy(policy),
    );
    let (mut state, store) = match &setup.auth {
        Some(auth) => super::tests::test_router_app_state_with_auth(auth).await,
        None => super::tests::test_router_app_state().await,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    for name in ["alpha", "beta"] {
        let backend = Arc::new(Backend::new(
            name,
            BackendConfig::default(),
            &FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        backend.set_transport_for_test(Arc::new(Scripted {
            calls: Arc::clone(&calls),
            error: setup.backend_error,
        }));
        assert!(state_mut.backends.register(backend), "fixture registration");
    }
    if let Some(config) = setup.agent_identity {
        state_mut.agent_identity_config = config;
    }
    let mut meta = MetaMcp::new(Arc::clone(&state_mut.backends));
    meta.enable_transparency_log(Arc::clone(&log));
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(Arc::clone(&log));
    let router = create_router(Arc::clone(&state));
    Fixture {
        state,
        router,
        log,
        path,
        calls,
        _dirs: (audit, store),
    }
}

/// An auth config with one key, `k`, scoped to `alpha`.
fn key_for_alpha(denied_tools: Option<Vec<String>>) -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(crate::config::api_key_digest_spec(b"k")),
            expires_at: None,
            name: "alpha-client".to_string(),
            rate_limit: 0,
            backends: vec!["alpha".to_string()],
            allowed_tools: None,
            denied_tools,
            admin: false,
        }],
        public_paths: vec!["/health".to_string()],
        client_circuit_breaker: None,
        single_user: false,
    }
}

/// How a cell presents itself to the gateway.
enum Caller {
    Anonymous,
    Oidc,
    Key,
    /// Anonymous, carrying an `mcp-session-id` header.
    Session,
}

async fn post(fx: &Fixture, backend: &str, body: &str, caller: &Caller) -> (StatusCode, Value) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{backend}"))
        .header("content-type", "application/json");
    if matches!(caller, Caller::Key) {
        builder = builder.header("authorization", "Bearer k");
    }
    if matches!(caller, Caller::Session) {
        builder = builder.header("mcp-session-id", "sess-d2");
    }
    let mut request = builder
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    if matches!(caller, Caller::Oidc) {
        // Auth is off in the OIDC cells, so the middleware leaves it in place.
        request.extensions_mut().insert(VerifiedIdentity {
            subject: "1".to_string(),
            email: "one@example.invalid".to_string(),
            name: None,
            groups: vec![],
            issuer: "https://a.example.invalid".to_string(),
        });
    }
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn tools_call(tool: &str) -> String {
    json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
           "params": {"name": tool, "arguments": {"q": 1}}})
    .to_string()
}

/// Every invocation record in the log (entries that carry a `request_hash`).
fn invocations(fx: &Fixture) -> Vec<Value> {
    std::fs::read_to_string(&fx.path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry.get("request_hash").is_some())
        .collect()
}

fn only_invocation(fx: &Fixture) -> Value {
    let mut all = invocations(fx);
    assert_eq!(
        all.len(),
        1,
        "expected exactly one invocation record: {all:?}"
    );
    all.remove(0)
}

/// MIK-7570.ATTEST.1: the attestation token is stripped from the request
/// after the audit hash, so the hash still covers the params as sent (D2-e)
/// while the token string itself never reaches the log.
#[tokio::test]
async fn direct_audit_hash_covers_the_token_as_sent() {
    let fx = fixture(Setup::default()).await;
    let token = "tok-audit-as-sent";
    let params = json!({"name": "t", "arguments": {"q": 1},
                        "_meta": {(crate::protocol::mrtr::ATTESTATION_META): token}});
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": params});
    let (status, answer) = post(&fx, "alpha", &body.to_string(), &Caller::Oidc).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let expected = format!("sha256:{}", crate::hashing::canonical_json_sha256(&params));
    assert_eq!(only_invocation(&fx)["request_hash"], expected.as_str());
    let raw = std::fs::read_to_string(&fx.path).unwrap();
    assert!(!raw.contains(token), "the token reached the audit log");
}

/// D2-T1. A verified caller's direct tool call writes one full record.
#[tokio::test]
async fn direct_tool_call_writes_invocation_record() {
    let fx = fixture(Setup::default()).await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Oidc).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let entry = only_invocation(&fx);
    assert_eq!(entry["route"], "direct", "{entry}");
    assert_eq!(entry["server"], "alpha");
    assert_eq!(entry["tool"], "t");
    assert_eq!(entry["outcome"], "ok");
    assert_eq!(entry["schema_version"], 2);
    assert!(entry.get("error_code").is_none(), "{entry}");
    assert_eq!(entry["who"]["subject"], "1", "{entry}");
    assert_eq!(entry["who"]["authority"], "https://a.example.invalid");
    let params = json!({"name": "t", "arguments": {"q": 1}});
    let expected = format!("sha256:{}", crate::hashing::canonical_json_sha256(&params));
    assert_eq!(
        entry["request_hash"],
        expected.as_str(),
        "hash of params as sent"
    );
    let delivered = format!("sha256:{}", crate::hashing::canonical_json_sha256(&body));
    assert_eq!(
        entry["response_hash"],
        delivered.as_str(),
        "hash of the body delivered"
    );
    let raw = std::fs::read_to_string(&fx.path).unwrap();
    assert!(
        !raw.contains("one@example.invalid"),
        "an email reached the log"
    );
}

/// D2-T1b. D1's writer names its route too.
#[tokio::test]
async fn meta_invocation_record_says_route_meta() {
    let fx = fixture(Setup::default()).await;
    let caller = MetaMcpCallerContext {
        is_modern: false,
        era: crate::protocol::meta::Era::Legacy,
        ..anonymous_caller()
    };
    let _ = fx
        .state
        .meta_mcp
        .handle_tools_call(
            RequestId::Number(1),
            "gateway_invoke",
            json!({"server": "alpha", "tool": "t", "arguments": {}}),
            None,
            caller,
        )
        .await;
    assert_eq!(only_invocation(&fx)["route"], "meta");
}

/// D2-T2. A scope refusal is a `denied` record that names the tool.
#[tokio::test]
async fn direct_scope_refusal_is_denied_record() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx, "beta", &tools_call("t"), &Caller::Key).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], -32003, "{body}");

    let entry = only_invocation(&fx);
    assert_eq!(entry["outcome"], "denied", "{entry}");
    assert_eq!(entry["error_code"], -32003);
    assert_eq!(entry["server"], "beta");
    assert_eq!(entry["tool"], "t", "the refusal carries the tool name");
    assert_eq!(entry["who"]["credential_kind"], "api_key");
    assert!(entry.get("response_hash").is_none(), "{entry}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0);
}

/// D2-T3. An authorizer refusal (`denied_tools`) is `denied`.
#[tokio::test]
async fn direct_authorizer_refusal_is_denied_record() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(Some(vec!["t".to_string()]))),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Key).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let entry = only_invocation(&fx);
    assert_eq!(entry["outcome"], "denied", "{entry}");
    assert_eq!(entry["tool"], "t");
}

/// D2-T5, positive control. Only tool calls are invocations.
#[tokio::test]
async fn direct_tools_list_writes_no_record() {
    let fx = fixture(Setup::default()).await;
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string();
    let (status, body) = post(&fx, "alpha", &list, &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(invocations(&fx), Vec::<Value>::new());
}

/// D2-T6. With auth on, a failed append withholds the result.
#[tokio::test]
async fn direct_append_failure_withholds_result() {
    let fx = fixture(Setup {
        fail_closed: true,
        ..Setup::default()
    })
    .await;
    fx.log.fail_next_append_for_test();
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], -32005, "{body}");
    assert_eq!(body["id"], 5, "the caller's id is kept");
    assert!(
        body.get("result").is_none(),
        "a result was delivered: {body}"
    );
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "the call did run");
}

/// D2-T6b, positive control. With auth off the same failure is only logged.
#[tokio::test]
async fn direct_append_failure_best_effort_still_answers() {
    let fx = fixture(Setup::default()).await;
    fx.log.fail_next_append_for_test();
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("result").is_some(), "{body}");
}

/// D2-T7, positive control. The C5 agent-identity refusal, checked before
/// the body is read, writes no record (as on the meta route).
#[tokio::test]
async fn agent_identity_refusal_writes_no_record() {
    let fx = fixture(Setup {
        agent_identity: Some(crate::config::AgentIdentityConfig {
            enabled: true,
            require_id: true,
            known_agents: vec![],
            ..Default::default()
        }),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(invocations(&fx), Vec::<Value>::new());
}

/// D2-T8, positive control. Moving the scope check below the body read must
/// not make an unknown backend distinguishable from a forbidden one.
#[tokio::test]
async fn scoped_key_gets_403_for_unknown_backend() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(None)),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx, "nope", &tools_call("t"), &Caller::Key).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], -32003, "{body}");
    let entry = only_invocation(&fx);
    assert_eq!(
        (&entry["outcome"], &entry["tool"]),
        (&json!("denied"), &json!("t"))
    );
}

/// D2-T9. A tools/call with no params names no tool, so there is nothing to
/// authorize: it is refused (400, -32602), never forwarded, and recorded as
/// `invalid` with no `tool`.
#[tokio::test]
async fn malformed_direct_tools_call_is_invalid() {
    let fx = fixture(Setup::default()).await;
    let bare = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call"}).to_string();
    let (status, body) = post(&fx, "alpha", &bare, &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32602, "{body}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "reached the backend");
    let entry = only_invocation(&fx);
    assert_eq!(entry["outcome"], "invalid", "{entry}");
    assert_eq!(entry["error_code"], -32602, "{entry}");
    assert!(entry.get("tool").is_none(), "{entry}");
}

/// D2-T9c. Params with no `name`, or an empty one, are refused the same way.
/// Restoring the early `return None` in `apply_backend_tool_call_security`
/// forwards them unauthorized and turns this red.
#[tokio::test]
async fn nameless_direct_tools_call_is_refused() {
    let fx = fixture(Setup::default()).await;
    for params in [
        json!({"arguments": {}}),
        json!({"name": "", "arguments": {}}),
    ] {
        let body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": params});
        let (status, answer) = post(&fx, "alpha", &body.to_string(), &Caller::Anonymous).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{params}: {answer}");
        assert_eq!(answer["error"]["code"], -32602, "{params}: {answer}");
    }
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "reached the backend");
    let all = invocations(&fx);
    assert_eq!(all.len(), 2, "{all:?}");
    for entry in all {
        assert_eq!(entry["outcome"], "invalid", "{entry}");
        assert!(entry.get("tool").is_none(), "{entry}");
    }
}

/// D2-T9d. An envelope `parse_request` refuses (a wrong `jsonrpc` version)
/// is `invalid` too. The slot is filled before the parse, so moving the fill
/// below it turns this red.
#[tokio::test]
async fn unparseable_direct_tools_call_envelope_is_invalid() {
    let fx = fixture(Setup::default()).await;
    let bad = json!({"jsonrpc": "1.0", "id": 1, "method": "tools/call"}).to_string();
    let (status, body) = post(&fx, "alpha", &bad, &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let entry = only_invocation(&fx);
    assert_eq!(entry["outcome"], "invalid", "{entry}");
    assert_eq!(entry["error_code"], -32600, "{entry}");
    assert!(entry.get("tool").is_none(), "{entry}");
}

/// D2-T9b, positive control. A body that is not JSON has no method, so no
/// record, the same as the meta route.
#[tokio::test]
async fn non_json_body_writes_no_record() {
    let fx = fixture(Setup::default()).await;
    let (status, _) = post(&fx, "alpha", "not json", &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(invocations(&fx), Vec::<Value>::new());
}

/// D2-T11. The correlation key is the caller's W3C trace id when it sent
/// one, else a minted trace id; never the `mcp-session-id` it sent (D2-f).
#[tokio::test]
async fn direct_record_correlates_on_trace_id() {
    let fx = fixture(Setup::default()).await;
    let otel = "4bf92f3577b34da6a3ce929d0e0e4736";
    let traced = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "name": "t", "arguments": {},
        "_meta": {"traceparent": format!("00-{otel}-00f067aa0ba902b7-01")}}})
    .to_string();
    let _ = post(&fx, "alpha", &traced, &Caller::Anonymous).await;
    let _ = post(&fx, "alpha", &tools_call("t"), &Caller::Session).await;

    let all = invocations(&fx);
    assert_eq!(all.len(), 2, "{all:?}");
    assert_eq!(all[0]["correlation_source"], "otel_trace_id", "{}", all[0]);
    assert_eq!(all[0]["session_id"], otel);
    assert_eq!(all[0]["otel_trace_id"], otel);
    assert_eq!(all[1]["correlation_source"], "trace_id", "{}", all[1]);
    assert_eq!(all[1]["session_id"], all[1]["trace_id"]);
}

/// D2-T5b, positive control. D1 audits invocations only, so the direct
/// route's other caller-data methods write no record either.
#[tokio::test]
async fn direct_non_tool_methods_write_no_record() {
    let fx = fixture(Setup::default()).await;
    for (method, params) in [
        ("resources/read", json!({"uri": "file:///x"})),
        ("prompts/get", json!({"name": "p"})),
    ] {
        let body = json!({"jsonrpc": "2.0", "id": 3, "method": method, "params": params});
        let _ = post(&fx, "alpha", &body.to_string(), &Caller::Anonymous).await;
    }
    assert_eq!(invocations(&fx), Vec::<Value>::new());
}

/// D2-T10. A backend's own -32005 is the backend's error, not the log being
/// down: it is recorded, never suppressed.
#[tokio::test]
async fn backend_503_32005_is_recorded_as_error() {
    let fx = fixture(Setup {
        backend_error: Some(-32005),
        ..Setup::default()
    })
    .await;
    let (_, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    assert_eq!(body["error"]["code"], -32005, "{body}");
    let entry = only_invocation(&fx);
    assert_eq!(entry["outcome"], "error", "{entry}");
    assert_eq!(entry["error_code"], -32005);
}
