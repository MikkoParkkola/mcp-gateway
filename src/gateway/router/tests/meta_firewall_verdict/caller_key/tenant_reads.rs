// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-7116.MIN.2 red tests, rows 2 and 2b of the design's red-test order
//! (docs/design/2026-10-01-min2-min4-tenant-reads.md §6.1).
//!
//! One `caller_key` may read at most one tenant inside the window, whatever
//! route, session or concurrency the reads arrive on. Every row runs the real
//! router with two `Firewall` instances built from one config, as startup
//! does, so a history held per `TenantGuard` cannot pass. The TENANT.1 guard
//! stays off (`enabled: false`): only `cross_tenant_reads` may change an
//! outcome. Each row first runs its flow with the mode `off` as a control
//! (both tenants delivered), so a "B refused" assertion cannot pass vacuously.

use super::super::TOOL;
use super::{Caller, Outcome, api_key, call_with, direct_call_with, keys, send};
use crate::config::AuthConfig;
use crate::gateway::router::AppState;
use crate::gateway::router::create_router;
use crate::protocol::{JsonRpcNotification, JsonRpcResponse, RequestId};
use crate::security::TransparencyLogger;
use crate::security::firewall::tenant_guard::{CrossTenantReads, TenantGuardConfig};
use crate::security::firewall::tenant_reads::ReadHistory;
use crate::security::firewall::{Firewall, FirewallConfig};
use crate::security::hash_argument;
use crate::security::transparency_log::TransparencyLogConfig;
use crate::transport::{Transport, notification_sink};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::sync::Arc;

const A: &str = "cust-a";
const B: &str = "cust-b";

use Outcome::Delivered;

/// Attribution on `customer_id`, the TENANT.1 guard off, the MIN.2 verdict
/// in `mode`, on the process history `reads` (startup shares one between
/// both firewalls, `Gateway::response_firewall`).
fn reads_firewall(
    mode: CrossTenantReads,
    window_secs: u64,
    reads: &Arc<ReadHistory>,
    arg_keys: &[&str],
    keys: &Arc<crate::protocol::continuation::ContinuationState>,
) -> Arc<Firewall> {
    Arc::new(
        Firewall::from_config(
            FirewallConfig {
                tenant_guard: TenantGuardConfig {
                    enabled: false,
                    window_secs,
                    arg_keys: arg_keys.iter().map(|k| (*k).to_string()).collect(),
                    cross_tenant_reads: mode,
                    ..TenantGuardConfig::default()
                },
                ..FirewallConfig::default()
            },
            None,
        )
        .with_reads(Arc::clone(reads))
        .with_continuations(Arc::clone(keys)),
    )
}

/// The router with one API-key caller and production's split firewall: one
/// instance on `AppState`, another on the Meta-MCP, from one config.
async fn router(mode: CrossTenantReads) -> (axum::Router, tempfile::TempDir) {
    windowed_router(mode, 3600).await
}

async fn windowed_router(mode: CrossTenantReads, window: u64) -> (axum::Router, tempfile::TempDir) {
    let (state, store) = split_state(mode, window).await;
    (create_router(state), store)
}

async fn split_state(mode: CrossTenantReads, window: u64) -> (Arc<AppState>, tempfile::TempDir) {
    keyed_state(mode, window, &["customer_id"]).await
}

/// [`split_state`] attributing on `arg_keys`.
async fn keyed_state(
    mode: CrossTenantReads,
    window: u64,
    arg_keys: &[&str],
) -> (Arc<AppState>, tempfile::TempDir) {
    let reads = ReadHistory::shared();
    // One keyring for both, as startup pairs them (#2210, MIK-8276).
    let keys = Arc::new(crate::protocol::continuation::ContinuationState::new());
    let (handler, meta) = (
        reads_firewall(mode, window, &reads, arg_keys, &keys),
        reads_firewall(mode, window, &reads, arg_keys, &keys),
    );
    let (state, store) =
        super::super::state_with_firewalls_and_auth(handler, meta, &one_key()).await;
    state
        .backends
        .get("demo")
        .expect("the fixture registers demo")
        .set_transport_for_test(Arc::new(NotifyingBackend) as Arc<dyn Transport>);
    (state, store)
}

/// A backend whose `tools/call` result names no tenant. With
/// `arguments.notify` set it first publishes a request-scoped notification
/// naming B, the way a backend reader hands one to the in-flight request.
struct NotifyingBackend;

#[async_trait]
impl Transport for NotifyingBackend {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        if method == "tools/list" {
            let mut tool = json!({ "name": TOOL, "inputSchema": { "type": "object" } });
            // Asked with `probe`, the descriptor names B in a field the list
            // normalisation does not keep.
            if params.as_ref().and_then(|p| p.get("probe")) == Some(&json!("tenant-b")) {
                tool["customer_id"] = json!(B);
            }
            return Ok(JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                json!({ "tools": [tool] }),
            ));
        }
        let notify = params
            .as_ref()
            .and_then(|p| p.pointer("/arguments/notify"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if notify {
            notification_sink::publish(vec![JsonRpcNotification {
                jsonrpc: "2.0".to_string(),
                method: "notifications/resources/updated".to_string(),
                params: Some(json!({ "uri": "rows://latest", "customer_id": B })),
            }]);
        }
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({ "content": [{ "type": "text", "text": "ok" }], "isError": false }),
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

/// [`router`] in observe mode with a transparency log on the Meta-MCP.
async fn logged_router() -> (axum::Router, tempfile::TempDir, tempfile::TempDir) {
    logged_router_in(CrossTenantReads::Observe).await
}

/// [`logged_router`] in `mode`.
async fn logged_router_in(
    mode: CrossTenantReads,
) -> (axum::Router, tempfile::TempDir, tempfile::TempDir) {
    let (state, store) = split_state(mode, 3600).await;
    let log_dir = tempfile::tempdir().expect("a log directory");
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: log_dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "min2".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log"),
    );
    let mut app = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("fixture state is exclusive"));
    let mut meta =
        Arc::try_unwrap(app.meta_mcp).unwrap_or_else(|_| panic!("fixture meta is exclusive"));
    meta.enable_transparency_log(log);
    app.meta_mcp = Arc::new(meta);
    (create_router(Arc::new(app)), store, log_dir)
}

fn log_lines(dir: &tempfile::TempDir) -> Vec<String> {
    std::fs::read_to_string(dir.path().join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

/// Records whose `cross_tenant_read` is `flagged`, at the top level or one
/// envelope down.
fn flagged(lines: &[String]) -> usize {
    lines
        .iter()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|record| record_field(record, "cross_tenant_read") == Some("flagged"))
        .count()
}

fn record_field<'a>(record: &'a Value, name: &str) -> Option<&'a str> {
    record.get(name).and_then(Value::as_str).or_else(|| {
        record
            .as_object()?
            .values()
            .find_map(|inner| inner.get(name).and_then(Value::as_str))
    })
}

fn one_key() -> AuthConfig {
    keys(vec![api_key("key-one", "one")])
}

fn caller() -> Caller {
    Caller {
        bearer: Some("key-one"),
        ..Caller::default()
    }
}

fn reading(tenant: &str) -> Value {
    json!({ "customer_id": tenant })
}

/// Concurrent stateless POSTs under one key, one reading A and one reading B.
async fn concurrent_pair(router: &axum::Router) -> [Outcome; 2] {
    let who = caller();
    let ((a, _, a_body), (b, _, b_body)) = tokio::join!(
        send(router, call_with(&who, true, None, 0, &reading(A))),
        send(router, call_with(&who, true, None, 1, &reading(B))),
    );
    eprintln!("A: {a:?} {a_body}");
    eprintln!("B: {b:?} {b_body}");
    [a, b]
}

/// Two legacy sessions under one key: the first reads A, the second B.
async fn two_sessions(router: &axum::Router) -> (Outcome, Outcome) {
    let who = caller();
    let (first, s1, body) = send(router, call_with(&who, false, None, 0, &reading(A))).await;
    eprintln!("session 1 A: {first:?} {s1:?} {body}");
    let (second, s2, body) = send(router, call_with(&who, false, None, 1, &reading(B))).await;
    eprintln!("session 2 B: {second:?} {s2:?} {body}");
    (first, second)
}

/// Row 2: concurrent stateless POSTs and two sessions under one `caller_key`,
/// reading A and B. Exactly one side is refused in block mode, whichever was
/// admitted first, and only the B side is flagged in observe mode.
#[tokio::test]
async fn concurrent_stateless_and_two_sessions_one_key() {
    // Control: with the verdict off, every read is delivered.
    let (off, _store) = router(CrossTenantReads::Off).await;
    let got = concurrent_pair(&off).await;
    assert_eq!(got, [Delivered, Delivered], "control: off delivers both");
    let (off, _store) = router(CrossTenantReads::Off).await;
    let (first, second) = two_sessions(&off).await;
    assert_eq!((first, second), (Delivered, Delivered), "control: off");

    // Block: two concurrent stateless reads serialize on one history entry.
    let (block, _store) = router(CrossTenantReads::Block).await;
    let got = concurrent_pair(&block).await;
    let delivered = got.iter().filter(|o| **o == Delivered).count();
    assert_eq!(
        delivered, 1,
        "one key read A and B concurrently; exactly one must be refused: {got:?}"
    );

    // Block: a second session under the same key shares the history.
    let (block, _store) = router(CrossTenantReads::Block).await;
    let (first, second) = two_sessions(&block).await;
    assert_eq!(first, Delivered, "the first tenant is ordinary");
    assert_ne!(
        second, Delivered,
        "a second session under one key read a second tenant"
    );

    // Observe: both delivered, and exactly the B read is flagged.
    let (observe, _store, log_dir) = logged_router().await;
    let who = caller();
    let (a, _, body) = send(&observe, call_with(&who, true, None, 0, &reading(A))).await;
    assert_eq!(a, Delivered, "{body}");
    let (b, _, body) = send(&observe, call_with(&who, true, None, 1, &reading(B))).await;
    assert_eq!(b, Delivered, "observe never withholds: {body}");
    let lines = log_lines(&log_dir);
    let b_hash = hash_argument(&json!(B));
    assert!(
        lines.iter().any(|line| line.contains(&b_hash)),
        "control: the B read is attributed in the log: {lines:#?}"
    );
    assert_eq!(
        flagged(&lines),
        1,
        "exactly the B read is flagged cross_tenant_read: {lines:#?}"
    );
}

/// MIK-7799: a judged POST answer is one record, not two. The verdict rides
/// the answer's own `response_delivery_attempt` record; no standalone
/// `tenant_read` event is written for it.
#[tokio::test]
async fn a_judged_answer_is_one_record() {
    let (observe, _store, log_dir) = logged_router().await;
    let who = caller();
    let (a, _, body) = send(&observe, call_with(&who, true, None, 0, &reading(A))).await;
    assert_eq!(a, Delivered, "{body}");
    let (b, _, body) = send(&observe, call_with(&who, true, None, 1, &reading(B))).await;
    assert_eq!(b, Delivered, "observe never withholds: {body}");
    let lines = log_lines(&log_dir);
    let records: Vec<Value> = lines
        .iter()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    let of = |event: &str| {
        records
            .iter()
            .filter(|r| record_field(r, "event") == Some(event))
            .count()
    };
    assert_eq!(
        of("tenant_read"),
        0,
        "no standalone tenant_read event for a POST answer: {lines:#?}"
    );
    let b_hash = hash_argument(&json!(B));
    let carrying = records.iter().find(|r| {
        record_field(r, "event") == Some("response_delivery_attempt")
            && record_field(r, "cross_tenant_read") == Some("flagged")
    });
    let carrying = carrying.unwrap_or_else(|| panic!("a flagged delivery record: {lines:#?}"));
    assert!(
        carrying.to_string().contains(&b_hash),
        "the delivery record names the B tenant: {carrying}"
    );
}

/// MIN.2 text: a test proves the block fires and that audit entries exist for
/// both the read and the block. Block mode with a log: A's read is delivered
/// and its record names tenant A with no verdict; B's read is withheld and
/// its record names tenant B with `cross_tenant_read: blocked`.
#[tokio::test]
async fn a_block_leaves_audit_entries_for_the_read_and_the_block() {
    let (block, _store, log_dir) = logged_router_in(CrossTenantReads::Block).await;
    let who = caller();
    let (a, _, body) = send(&block, call_with(&who, true, None, 0, &reading(A))).await;
    assert_eq!(a, Delivered, "the first tenant is ordinary: {body}");
    let (b, _, body) = send(&block, call_with(&who, true, None, 1, &reading(B))).await;
    assert_ne!(b, Delivered, "the block fires: {body}");
    assert!(
        body.to_string().contains("Response withheld"),
        "the refusal is the tenant guard's: {body}"
    );
    let records: Vec<Value> = log_lines(&log_dir)
        .iter()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    let naming = |tenant: &str| -> Vec<&Value> {
        let hash = hash_argument(&json!(tenant));
        records
            .iter()
            .filter(|r| {
                record_field(r, "event") == Some("response_delivery_attempt")
                    && r.to_string().contains(&hash)
            })
            .collect()
    };
    let read = naming(A);
    assert_eq!(
        read.len(),
        1,
        "one audit entry for the A read: {records:#?}"
    );
    assert_eq!(
        record_field(read[0], "cross_tenant_read"),
        None,
        "the read within the rule carries no verdict: {}",
        read[0]
    );
    let verdict = naming(B);
    assert_eq!(
        verdict.len(),
        1,
        "one audit entry for the block: {records:#?}"
    );
    assert_eq!(
        record_field(verdict[0], "cross_tenant_read"),
        Some("blocked"),
        "{}",
        verdict[0]
    );
}

/// Row 2b: A on `/mcp`, then B on `/mcp/{name}`, same key. The two routes
/// hold different `Firewall` instances; the history is the process's.
#[tokio::test]
async fn meta_and_direct_share_history() {
    let who = caller();

    // Control: off delivers B on the direct route.
    let (off, _store) = router(CrossTenantReads::Off).await;
    let (a, _, body) = send(&off, call_with(&who, true, None, 0, &reading(A))).await;
    assert_eq!(a, Delivered, "{body}");
    let (b, _, body) = send(&off, direct_call_with("key-one", 1, &reading(B))).await;
    assert_eq!(b, Delivered, "control: off delivers B on /mcp/demo: {body}");

    let (block, _store) = router(CrossTenantReads::Block).await;
    let (a, _, body) = send(&block, call_with(&who, true, None, 0, &reading(A))).await;
    assert_eq!(a, Delivered, "{body}");
    let (b, _, body) = send(&block, direct_call_with("key-one", 1, &reading(B))).await;
    assert_ne!(
        b, Delivered,
        "A on /mcp and B on /mcp/demo under one key must share one history: {body}"
    );
}

/// Round 9 (review P1): a direct `tools/list` is read before it is
/// normalised. A descriptor naming B in a field the normalisation drops is
/// still a read of B: after A, block refuses it.
#[tokio::test]
async fn direct_list_reads_before_normalising() {
    let list = || {
        let body = json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/list",
            "params": { "probe": "tenant-b" }
        });
        axum::http::Request::builder()
            .method("POST")
            .uri("/mcp/demo")
            .header("content-type", "application/json")
            .header("authorization", "Bearer key-one")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    };
    let who = caller();
    for (mode, refused) in [
        (CrossTenantReads::Off, false),
        (CrossTenantReads::Block, true),
    ] {
        let (router, _store) = router(mode).await;
        let (a, _, body) = send(&router, call_with(&who, true, None, 0, &reading(A))).await;
        assert_eq!(a, Delivered, "{body}");
        let (_, _, body) = send(&router, list()).await;
        assert_eq!(
            body.get("error").is_some(),
            refused,
            "{mode:?}: a list naming B only in a dropped field, after A: {body}"
        );
    }
}

/// POST `tools/call` with `Accept: text/event-stream`; the whole body, read
/// to its end under a bound (a POST stream closes with its answer).
async fn send_sse(router: &axum::Router, n: usize, arguments: &Value) -> String {
    use tower::ServiceExt;
    let mut request = call_with(&caller(), true, None, n, arguments);
    request.headers_mut().insert(
        axum::http::header::ACCEPT,
        axum::http::HeaderValue::from_static("application/json, text/event-stream"),
    );
    let response = router.clone().oneshot(request).await.unwrap();
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        axum::body::to_bytes(response.into_body(), usize::MAX),
    )
    .await
    .expect("a POST stream ends with its answer")
    .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Row 1 (H6): an A result, then a POST-SSE call whose dispatch finishes
/// first, with a B notification drained into the fallback body. Observe:
/// the B frame is flagged in the log. Block: the B notification is absent.
#[tokio::test]
async fn dispatch_first_post_b_notification_after_a_result() {
    let who = caller();
    let notify = json!({ "notify": true });

    // Control: with the verdict off, the B notification reaches the body.
    let (off, _store) = router(CrossTenantReads::Off).await;
    let (a, _, body) = send(&off, call_with(&who, true, None, 0, &reading(A))).await;
    assert_eq!(a, Delivered, "{body}");
    let body = send_sse(&off, 1, &notify).await;
    assert!(
        body.contains(B),
        "control: off delivers the B notification on the POST stream: {body}"
    );

    // Block: the B notification is withheld; the call's own answer is not.
    let (block, _store) = router(CrossTenantReads::Block).await;
    let (a, _, body) = send(&block, call_with(&who, true, None, 0, &reading(A))).await;
    assert_eq!(a, Delivered, "{body}");
    let body = send_sse(&block, 1, &notify).await;
    assert!(
        body.contains(r#""result""#),
        "the call's answer is still framed: {body}"
    );
    assert!(
        !body.contains(B),
        "a B notification after an A read reached the POST-SSE body: {body}"
    );

    // Observe: delivered, and the B frame is flagged in the log.
    let (observe, _store, log_dir) = logged_router().await;
    let (a, _, body) = send(&observe, call_with(&who, true, None, 0, &reading(A))).await;
    assert_eq!(a, Delivered, "{body}");
    let body = send_sse(&observe, 1, &notify).await;
    assert!(body.contains(B), "observe never withholds: {body}");
    let lines = log_lines(&log_dir);
    assert_eq!(
        flagged(&lines),
        1,
        "the B notification is flagged cross_tenant_read: {lines:#?}"
    );
}

/// F3: an A answer whose body is not yet written stays reserved. The window
/// passes while the A body is held unread, then B is admitted, then A is
/// read: B is refused (block), because A was never emitted before B.
#[tokio::test]
async fn delayed_http_body_keeps_reservation() {
    use tower::ServiceExt;
    let who = caller();
    for mode in [CrossTenantReads::Off, CrossTenantReads::Block] {
        let (router, _store) = windowed_router(mode, 1).await;
        let held = router
            .clone()
            .oneshot(call_with(&who, true, None, 0, &reading(A)))
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
        let (b, _, body) = send(&router, call_with(&who, true, None, 1, &reading(B))).await;
        let a = axum::body::to_bytes(held.into_body(), usize::MAX)
            .await
            .unwrap();
        let a = String::from_utf8_lossy(&a).into_owned();
        assert!(a.contains(r#""result""#), "the held A answer: {a}");
        if mode == CrossTenantReads::Off {
            assert_eq!(b, Delivered, "control: off delivers B: {body}");
        } else {
            assert_ne!(
                b, Delivered,
                "B was admitted while the A body was still unwritten: {body}"
            );
        }
    }
}

/// F3 on POST-SSE (review finding 1): a dispatch-first stream answering A,
/// held unread past the window while B is admitted: B is still refused,
/// because nothing commits A before the stream is read.
#[tokio::test]
async fn delayed_sse_body_keeps_reservation() {
    use tower::ServiceExt;
    let who = caller();
    for mode in [CrossTenantReads::Off, CrossTenantReads::Block] {
        let (router, _store) = windowed_router(mode, 1).await;
        let mut request = call_with(&who, true, None, 0, &reading(A));
        request.headers_mut().insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static("application/json, text/event-stream"),
        );
        let held = router.clone().oneshot(request).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
        let (b, _, body) = send(&router, call_with(&who, true, None, 1, &reading(B))).await;
        let a = axum::body::to_bytes(held.into_body(), usize::MAX)
            .await
            .unwrap();
        let a = String::from_utf8_lossy(&a).into_owned();
        assert!(a.contains(r#""result""#), "the held A answer: {a}");
        if mode == CrossTenantReads::Off {
            assert_eq!(b, Delivered, "control: off delivers B: {body}");
        } else {
            assert_ne!(
                b, Delivered,
                "B was admitted while the A stream was still unread: {body}"
            );
        }
    }
}

#[path = "tenant_read_streams.rs"]
mod streams;
