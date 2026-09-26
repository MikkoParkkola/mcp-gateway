// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D1-f fail-closed: a failed audit append withholds the result, refuses the
//! next calls before dispatch, and unreadies the pod until an append succeeds
//! (D1-T17, T17b, T18, and the Revision 3 readiness-driven recovery).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use super::tests::test_router_app_state;
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext, anonymous_caller};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::TransparencyLogger;
use crate::security::audit::AuditFailurePolicy;
use crate::security::transparency_log::TransparencyLogConfig;
use crate::transport::Transport;

struct Counting(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl Transport for Counting {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
        ))
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
    calls: Arc<AtomicUsize>,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

/// One logger, shared by the meta route and `AppState`, as the server wires it.
async fn fixture(policy: AuditFailurePolicy) -> Fixture {
    let audit = tempfile::tempdir().unwrap();
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: audit
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "d1".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log")
        .with_failure_policy(policy),
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Counting(Arc::clone(&calls))));
    let (mut state, store) = test_router_app_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    assert!(state_mut.backends.register(backend), "fixture registration");
    let mut meta = MetaMcp::new(Arc::clone(&state_mut.backends));
    meta.enable_transparency_log(Arc::clone(&log));
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(Arc::clone(&log));
    let router = create_router(Arc::clone(&state));
    Fixture {
        state,
        router,
        log,
        calls,
        _dirs: (audit, store),
    }
}

fn caller() -> MetaMcpCallerContext<'static> {
    MetaMcpCallerContext {
        is_modern: false,
        era: crate::protocol::meta::Era::Legacy,
        ..anonymous_caller()
    }
}

async fn invoke(fx: &Fixture, id: i64) -> JsonRpcResponse {
    fx.state
        .meta_mcp
        .handle_tools_call(
            RequestId::Number(id),
            "gateway_invoke",
            json!({"server": "alpha", "tool": "read", "arguments": {}}),
            None,
            caller(),
        )
        .await
}

/// The refusal D1-f specifies: JSON-RPC -32005 carrying HTTP 503, no result.
fn assert_audit_unavailable(response: &JsonRpcResponse, what: &str) {
    assert!(response.result.is_none(), "{what}: a result was delivered");
    let error = response
        .error
        .as_ref()
        .unwrap_or_else(|| panic!("{what}: no error"));
    assert_eq!(error.code, -32005, "{what}: {error:?}");
    let status = error
        .data
        .as_ref()
        .and_then(|d| d.get(crate::gateway::authz::HTTP_STATUS_DATA_KEY));
    assert_eq!(status, Some(&json!(503)), "{what}: {error:?}");
}

async fn readyz(fx: &Fixture) -> StatusCode {
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/readyz")
        .body(axum::body::Body::empty())
        .unwrap();
    fx.router.clone().oneshot(request).await.unwrap().status()
}

/// D1-T17. With auth on (`FailClosed`): call 1's append fails, so its result
/// is withheld; call 2 is refused before dispatch; `/readyz` is 503 between
/// them; call 3 after storage heals succeeds and readiness returns.
///
/// The counter is 4, not the 2 the design table states: Revision 3 makes
/// `/readyz` itself attempt the probe append while degraded, and both
/// readiness checks below run while the seam still fails.
#[tokio::test]
async fn append_failure_refuses_call_and_unreadies() {
    let fx = fixture(AuditFailurePolicy::FailClosed).await;
    fx.log.set_append_failure_for_test(true);

    let first = invoke(&fx, 1).await;
    assert_audit_unavailable(&first, "call 1");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "call 1 did run");
    assert_eq!(
        readyz(&fx).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "after call 1"
    );

    let second = invoke(&fx, 2).await;
    assert_audit_unavailable(&second, "call 2");
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "call 2 must be refused before dispatch"
    );
    assert_eq!(
        readyz(&fx).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "after call 2"
    );

    fx.log.set_append_failure_for_test(false);
    let third = invoke(&fx, 3).await;
    assert!(third.error.is_none(), "call 3: {:?}", third.error);
    assert_eq!(fx.calls.load(Ordering::SeqCst), 2, "call 3 ran");
    assert_eq!(readyz(&fx).await, StatusCode::OK, "healed");
    assert_eq!(fx.log.append_failures(), 4);
}

/// D1-T17b, positive control. Auth off (`BestEffort`): the same failure is
/// logged and the call answered.
#[tokio::test]
async fn append_failure_with_auth_off_still_answers() {
    let fx = fixture(AuditFailurePolicy::BestEffort).await;
    fx.log.set_append_failure_for_test(true);
    let response = invoke(&fx, 1).await;
    assert!(response.error.is_none(), "{:?}", response.error);
    assert!(response.result.is_some());
    assert_eq!(readyz(&fx).await, StatusCode::OK);
}

/// D1-T18. The direct route writes no record (D2) but must not serve while
/// the log is down, or it is a second, unaudited route.
#[tokio::test]
async fn direct_route_refused_while_degraded() {
    let fx = fixture(AuditFailurePolicy::FailClosed).await;
    fx.log.set_append_failure_for_test(true);
    let _ = invoke(&fx, 1).await;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/alpha")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        ))
        .unwrap();
    let status = fx.router.clone().oneshot(request).await.unwrap().status();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

/// Revision 3. A pod out of the Service gets no calls, so `/readyz` alone
/// must be able to recover it once storage heals.
#[tokio::test]
async fn readyz_alone_recovers_after_storage_heals() {
    let fx = fixture(AuditFailurePolicy::FailClosed).await;
    fx.log.set_append_failure_for_test(true);
    let _ = invoke(&fx, 1).await;
    assert_eq!(
        readyz(&fx).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "degraded"
    );
    assert_eq!(
        fx.log.last_failure_cause(),
        Some("io_error"),
        "the cause is named"
    );
    fx.log.set_append_failure_for_test(false);
    assert_eq!(
        readyz(&fx).await,
        StatusCode::OK,
        "readiness probe recovered it"
    );
    assert!(!fx.log.is_degraded());
}

// ── F20: a stalled audit disk ───────────────────────────────────────────────

const F20_BOUND: Duration = Duration::from_millis(200);

async fn readyz_body(fx: &Fixture) -> (StatusCode, String) {
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/readyz")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// F20 T1 + `/readyz`. `FailClosed`: the stuck append answers 503 within the
/// bound, and `/readyz` names the stall.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_append_times_out_with_503_and_readyz_reports_stalled() {
    let fx = fixture(AuditFailurePolicy::FailClosed).await;
    let release = fx.log.stall_next_write_for_test(F20_BOUND);
    let start = std::time::Instant::now();
    let first = invoke(&fx, 1).await;
    assert!(
        start.elapsed() < F20_BOUND * 5,
        "bounded: {:?}",
        start.elapsed()
    );
    assert_audit_unavailable(&first, "stalled call");
    assert!(fx.log.is_stalled());
    let (status, body) = readyz_body(&fx).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, "audit log unavailable: stalled");
    release.release();
}

/// F20 T1 `BestEffort`: results are delivered during a stall, the second call
/// at once, and `/readyz` stays 200.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn best_effort_stall_delivers_result_and_stays_ready() {
    let fx = fixture(AuditFailurePolicy::BestEffort).await;
    let release = fx.log.stall_next_write_for_test(F20_BOUND);
    let first = invoke(&fx, 1).await;
    assert!(first.error.is_none(), "{:?}", first.error);
    assert!(fx.log.is_stalled());
    let start = std::time::Instant::now();
    let second = invoke(&fx, 2).await;
    assert!(second.error.is_none(), "{:?}", second.error);
    assert!(start.elapsed() < F20_BOUND, "no wait while stalled");
    assert_eq!(readyz(&fx).await, StatusCode::OK);
    release.release();
}

/// F20 T6. The delivery-attempt append is bounded too: a stall answers 503
/// within the bound instead of pinning a worker (`FailClosed`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delivery_attempt_append_is_bounded() {
    use crate::gateway::meta_mcp::response_security::ResponseDeliveryContext;
    use crate::security::response_policy::{
        ResponseCorrelation, ResponseMutationPolicy, ResponsePolicyTarget,
    };
    let fx = fixture(AuditFailurePolicy::FailClosed).await;
    let release = fx.log.stall_next_write_for_test(F20_BOUND);
    let start = std::time::Instant::now();
    let response = fx
        .state
        .meta_mcp
        .finalize_response_for_delivery(
            JsonRpcResponse::success(RequestId::Number(1), json!({"content": []})),
            &ResponseDeliveryContext {
                method: "tools/call",
                targets: &[ResponsePolicyTarget {
                    server: "alpha".into(),
                    tool: "read".into(),
                }],
                correlation: ResponseCorrelation {
                    session_id: "s",
                    caller: "c",
                    external_server: "gateway",
                    external_tool: "gateway_invoke",
                },
                mutation: ResponseMutationPolicy::Redact,
                signing: None,
            },
        )
        .await;
    assert!(
        start.elapsed() < F20_BOUND * 5,
        "bounded: {:?}",
        start.elapsed()
    );
    assert_audit_unavailable(&response, "stalled delivery");
    assert!(fx.log.is_stalled());
    release.release();
}

/// F20 T3 / #1133 fail-fast. The invocation append stalls and the call is
/// withheld with 503. Delivering that 503 writes no delivery-attempt row:
/// the log is stalled, so the append refuses at once. When the stuck write
/// lands, the log holds an invocation record with no delivery attempt,
/// which is how a withheld result reads (UPGRADING item 50).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withheld_call_leaves_no_delivery_attempt_row() {
    use crate::gateway::meta_mcp::response_security::ResponseDeliveryContext;
    use crate::security::response_policy::{
        ResponseCorrelation, ResponseMutationPolicy, ResponsePolicyTarget,
    };
    let fx = fixture(AuditFailurePolicy::FailClosed).await;
    let release = fx.log.stall_next_write_for_test(F20_BOUND);
    let start = std::time::Instant::now();
    let withheld = invoke(&fx, 1).await;
    assert_audit_unavailable(&withheld, "stalled call");
    assert!(fx.log.is_stalled());
    // Refused at once: a delivery append that queued for the permit instead
    // would take a full bound before failing, and write nothing either way.
    let delivering = std::time::Instant::now();
    let delivered = fx
        .state
        .meta_mcp
        .finalize_response_for_delivery(
            withheld,
            &ResponseDeliveryContext {
                method: "tools/call",
                targets: &[ResponsePolicyTarget {
                    server: "alpha".into(),
                    tool: "read".into(),
                }],
                correlation: ResponseCorrelation {
                    session_id: "s",
                    caller: "c",
                    external_server: "gateway",
                    external_tool: "gateway_invoke",
                },
                mutation: ResponseMutationPolicy::Redact,
                signing: None,
            },
        )
        .await;
    assert_audit_unavailable(&delivered, "delivering the withheld call");
    assert!(
        delivering.elapsed() < F20_BOUND,
        "the delivery append waited: {:?}",
        delivering.elapsed()
    );
    assert!(
        start.elapsed() < F20_BOUND * 5,
        "bounded: {:?}",
        start.elapsed()
    );
    release.release();
    let rows = || -> Vec<Value> {
        std::fs::read_to_string(fx.log.path())
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    };
    for _ in 0..200 {
        if rows().iter().any(|r| r.get("request_hash").is_some()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Let anything queued behind the released write land before reading.
    for _ in 0..200 {
        if !fx.log.is_stalled() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(F20_BOUND * 2).await;
    let rows = rows();
    assert!(
        rows.iter().any(|r| r.get("request_hash").is_some()),
        "the late invocation record landed"
    );
    assert!(
        !rows
            .iter()
            .any(|r| r["event"] == "response_delivery_attempt"),
        "no delivery-attempt row for a withheld call: {rows:?}"
    );
}
