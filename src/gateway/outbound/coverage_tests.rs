// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Behaviour tests for outbound branches the coverage run left unexecuted:
//! the callback sink's refusals, `delivers_result` on non-answers, the
//! one-shot record fields, the judge's batch and withheld scan rows, and the
//! audit-failure paths of `recorded`, `record_fields` and `emit_http`.

use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};
use tempfile::TempDir;

use super::*;
use crate::events::CallbackFailure;
use crate::protocol::RequestId;
use crate::security::audit::AuditFailurePolicy;
use crate::security::firewall::tenant_guard::{CrossTenantReads, TenantGuardConfig};
use crate::security::firewall::{Firewall, FirewallConfig};
use crate::security::hash_argument;
use crate::security::{TransparencyLogConfig, TransparencyLogger};

const A: &str = "cust-a";
const B: &str = "cust-b";
const C: &str = "cust-c";
const KEY: &str = "api_key:one";
const OTHER: &str = "api_key:two";

fn firewall(mode: CrossTenantReads) -> Firewall {
    Firewall::from_config(
        FirewallConfig {
            tenant_guard: TenantGuardConfig {
                enabled: false,
                window_secs: 3600,
                arg_keys: vec!["customer_id".to_string()],
                cross_tenant_reads: mode,
                ..TenantGuardConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    )
}

/// An answer with id 1 to a call that named A: judged, attribution {A}.
fn read_a(fw: &Firewall) -> OutboundFrame {
    let answer = JsonRpcResponse::success(RequestId::Number(1), json!({ "ok": true }));
    delivered(
        fw,
        Some(KEY),
        Payload::Response(answer),
        Some(&json!({ "customer_id": A })),
        None,
    )
}

/// An answer with no id whose own document names A.
fn idless_answer_a(fw: &Firewall) -> OutboundFrame {
    let body = json!({ "jsonrpc": "2.0", "result": { "customer_id": A } });
    delivered(fw, Some(KEY), Payload::Answer(body), None, None)
}

/// A notification whose params name `tenant`, admitted for `KEY`.
fn admitted_note(fw: &Firewall, tenant: &str) -> OutboundFrame {
    let note = JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: "notifications/progress".to_string(),
        params: Some(json!({ "customer_id": tenant })),
    };
    match admit(fw, Some(KEY), Payload::Notification(note), None) {
        Admission::Admitted(frame) => frame,
        Admission::Blocked(e) => panic!("observe never withholds: {e:?}"),
    }
}

/// A callback frame naming A, judged for `KEY` under observe.
fn callback_a(fw: &Firewall) -> OutboundFrame {
    let read = attribute(fw, &json!({ "customer_id": A }));
    match callback_frame(
        Some(fw),
        Some(KEY),
        json!({ "data": { "note": "x" } }),
        Some(&read),
    ) {
        Admission::Admitted(frame) => frame,
        Admission::Blocked(e) => panic!("a first read is never blocked: {e:?}"),
    }
}

/// Whether a B answer for `KEY` is flagged now (a reservation is live).
fn b_flagged(fw: &Firewall) -> bool {
    let answer = JsonRpcResponse::success(RequestId::Number(9), json!({ "customer_id": B }));
    delivered(fw, Some(KEY), Payload::Response(answer), None, None).verdict()
        == Some(ReadVerdict::Flagged)
}

/// A transparency log in a fresh directory under `policy`.
fn logger(policy: AuditFailurePolicy) -> (TempDir, Arc<TransparencyLogger>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: dir.path().join("transparency.ndjson").display().to_string(),
        ..TransparencyLogConfig::default()
    }))
    .expect("log")
    .with_failure_policy(policy);
    (dir, Arc::new(log))
}

/// A `FailClosed` log whose next append fails once.
fn failing_log() -> (TempDir, Arc<TransparencyLogger>) {
    let (dir, log) = logger(AuditFailurePolicy::FailClosed);
    log.fail_next_append_for_test();
    (dir, log)
}

/// A sender that records whether it was called and reports a delivery.
fn recording_post(
    posted: &AtomicBool,
) -> impl FnOnce(Vec<u8>) -> std::future::Ready<CallbackSend<()>> + '_ {
    move |_body| {
        posted.store(true, Ordering::SeqCst);
        std::future::ready(CallbackSend::Sent(Ok(())))
    }
}

/// A callback judged for one principal is refused when sent as another, and
/// never posted. Mutant: the foreign-principal check removed.
#[tokio::test]
async fn a_callback_for_another_principal_is_refused_unsent() {
    let fw = firewall(CrossTenantReads::Observe);
    let posted = AtomicBool::new(false);
    let sent = send_callback(callback_a(&fw), OTHER, recording_post(&posted)).await;
    assert_eq!(sent, Err(CallbackFailure::ConnectionRefused));
    assert!(!posted.load(Ordering::SeqCst), "a foreign frame was posted");
    assert!(!b_flagged(&fw), "the dropped frame committed its read of A");

    // Control: the same frame sent as its own principal is posted.
    let posted = AtomicBool::new(false);
    let sent = send_callback(callback_a(&fw), KEY, recording_post(&posted)).await;
    assert_eq!(sent, Ok(()));
    assert!(
        posted.load(Ordering::SeqCst),
        "control: the owner's frame is posted"
    );
}

/// A frame that is not a callback body is refused and never posted.
/// Mutant: the `Payload::Callback` guard removed or widened.
#[tokio::test]
async fn a_non_callback_frame_is_refused_unsent() {
    let note = JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: "notifications/progress".to_string(),
        params: None,
    };
    let posted = AtomicBool::new(false);
    let frame = OutboundFrame::unjudged(Payload::Notification(note));
    let sent = send_callback(frame, KEY, recording_post(&posted)).await;
    assert_eq!(sent, Err(CallbackFailure::ConnectionRefused));
    assert!(
        !posted.load(Ordering::SeqCst),
        "a non-callback body was posted"
    );
}

/// A notification or a callback body delivers no result; an answer does.
/// Mutant: `_ => false` in `OutboundFrame::delivers_result` turned to `true`.
#[test]
fn a_non_answer_frame_delivers_no_result() {
    let note = JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: "notifications/progress".to_string(),
        params: None,
    };
    assert!(!OutboundFrame::unjudged(Payload::Notification(note)).delivers_result());
    assert!(!OutboundFrame::unjudged(Payload::Callback(json!({ "result": 1 }))).delivers_result());
    let answer = JsonRpcResponse::success(RequestId::Number(1), json!({}));
    assert!(
        OutboundFrame::unjudged(Payload::Response(answer)).delivers_result(),
        "control: an answer with a result delivers it"
    );
}

/// The record fields are taken once; a second take yields nothing.
/// Mutant: the `record_taken` early return removed.
#[test]
fn record_fields_are_taken_once() {
    let fw = firewall(CrossTenantReads::Observe);
    let mut frame = read_a(&fw);
    let first = frame
        .take_record_fields()
        .expect("a judged A read has fields");
    assert_eq!(first.get("event"), Some(&json!("tenant_read")));
    assert_eq!(
        frame.take_record_fields(),
        None,
        "the fields were taken twice"
    );
}

/// A batch is attributed the union of its items' attributions.
/// Mutant: the judge's `Payload::Batch` scan row returning nothing.
#[test]
fn a_batch_is_attributed_its_items_union() {
    let fw = firewall(CrossTenantReads::Observe);
    let items = vec![admitted_note(&fw, A), admitted_note(&fw, C)];
    let mut union = std::collections::BTreeSet::new();
    for item in &items {
        union.extend(
            item.assessment()
                .expect("judged")
                .attribution
                .tenants
                .clone(),
        );
    }
    assert_eq!(
        union,
        std::collections::BTreeSet::from([hash_argument(&json!(A)), hash_argument(&json!(C))]),
        "premise: the items name A and C"
    );
    match admit(&fw, Some(KEY), Payload::Batch(items), None) {
        Admission::Admitted(batch) => {
            let named = &batch.assessment().expect("judged").attribution.tenants;
            assert_eq!(named, &union, "the batch names its items' tenants");
        }
        Admission::Blocked(e) => panic!("observe never withholds: {e:?}"),
    }
}

/// A withheld payload emits nothing and so attributes nothing, even after
/// another tenant's read under block. Mutant: the `Payload::Withheld` scan
/// row attributing anything.
#[test]
fn a_withheld_payload_attributes_nothing() {
    let fw = firewall(CrossTenantReads::Block);
    let _a = read_a(&fw);
    match admit(&fw, Some(KEY), Payload::Withheld, None) {
        Admission::Admitted(frame) => {
            assert_eq!(frame.verdict(), None);
            let attribution = &frame.assessment().expect("judged").attribution;
            assert!(attribution.is_empty(), "attributed: {attribution:?}");
        }
        Admission::Blocked(e) => panic!("a withheld payload was blocked: {e:?}"),
    }
}

/// The request's tenants are charged only to a frame that delivers a result:
/// a notification "answering" a B request does not read B. Control: a
/// result answer to the same request is blocked. Mutant: `_ => false` in the
/// judge's private `delivers_result` turned to `true`.
#[test]
fn a_notification_is_not_charged_the_request_tenants() {
    let fw = firewall(CrossTenantReads::Block);
    let _a = read_a(&fw);
    let request = json!({ "customer_id": B });
    let hidden = ReadAttribution {
        tenants: [hash_argument(&json!(B))].into(),
        uninspected: false,
    };
    let note = JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: "notifications/progress".to_string(),
        params: None,
    };
    let frame = delivered(
        &fw,
        Some(KEY),
        Payload::Notification(note),
        Some(&request),
        Some(&hidden),
    );
    assert_eq!(frame.verdict(), None, "a notification was charged B");
    assert!(!frame.is_withheld());
    assert!(frame.assessment().expect("judged").attribution.is_empty());

    let answer = JsonRpcResponse::success(RequestId::Number(2), json!({ "ok": true }));
    let control = delivered(
        &fw,
        Some(KEY),
        Payload::Response(answer),
        Some(&request),
        None,
    );
    assert_eq!(
        control.verdict(),
        Some(ReadVerdict::Blocked),
        "control: a result answer is charged the request's B"
    );
}

/// The refusal an audit failure leaves: `AuditUnavailable`, no result.
fn assert_audit_refusal(frame: &OutboundFrame, id: Option<RequestId>) {
    let refusal = frame.response().expect("an answer frame stays an answer");
    assert_eq!(refusal.id, id);
    assert!(refusal.result.is_none(), "the refusal carries no result");
    let code = refusal.error.as_ref().expect("an error").code;
    assert_eq!(code, crate::Error::AuditUnavailable.to_rpc_code());
    assert!(!frame.delivers_result());
}

/// Under fail-closed, an answer whose record fails becomes the audit
/// refusal keeping its id. Mutant: `recorded` returning the frame unchanged
/// on a failed record, or dropping the id.
#[tokio::test]
async fn a_failed_record_refuses_an_answer_keeping_its_id() {
    let fw = firewall(CrossTenantReads::Observe);
    let (_dir, log) = failing_log();
    let frame = recorded(read_a(&fw), Some(&log)).await;
    assert_audit_refusal(&frame, Some(RequestId::Number(1)));
}

/// Under fail-closed, an id-less answer whose record fails becomes the audit
/// refusal with a null id. Mutant: the `None` id arm of `recorded` removed.
#[tokio::test]
async fn a_failed_record_refuses_an_idless_answer_with_a_null_id() {
    let fw = firewall(CrossTenantReads::Observe);
    let (_dir, log) = failing_log();
    let frame = recorded(idless_answer_a(&fw), Some(&log)).await;
    assert_audit_refusal(&frame, None);
}

/// Under fail-closed, a non-answer whose record fails is withheld; with the
/// append healthy it is written as built. Mutant: the `!is_answer` withhold
/// in `recorded` removed.
#[tokio::test]
async fn a_failed_record_withholds_a_non_answer() {
    let fw = firewall(CrossTenantReads::Observe);
    let (_dir, log) = failing_log();
    let frame = recorded(admitted_note(&fw, A), Some(&log)).await;
    assert!(frame.is_withheld(), "a notification was written unrecorded");

    let (_dir, healthy) = logger(AuditFailurePolicy::FailClosed);
    let frame = recorded(admitted_note(&fw, A), Some(&healthy)).await;
    assert!(
        !frame.is_withheld(),
        "control: a recorded notification is written"
    );
}

/// Under best effort a failed record still delivers (`true`); the same
/// failure under fail-closed does not, so the fault is real. Mutant: the
/// best-effort arm of `record_fields` returning `false`.
#[tokio::test]
async fn a_failed_record_under_best_effort_still_delivers() {
    let fw = firewall(CrossTenantReads::Observe);
    let fields = || read_a(&fw).take_record_fields().expect("fields");

    let (_dir, log) = logger(AuditFailurePolicy::BestEffort);
    log.fail_next_append_for_test();
    assert!(super::audit::record_fields(fields(), Some(&log)).await);

    let (_dir, log) = failing_log();
    assert!(
        !super::audit::record_fields(fields(), Some(&log)).await,
        "control: the injected fault fails the append under fail-closed"
    );
}

/// The JSON-RPC document of an HTTP response body.
async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("a JSON body")
}

/// A pending record that fails under fail-closed turns the HTTP answer into
/// a 503 audit refusal keeping the answer's id and session header, and
/// reports it was not written as built. Mutant: `emit_pending` ignoring the
/// failed write, the held id, or the session header.
#[tokio::test]
async fn a_failed_pending_record_refuses_the_http_answer_with_its_id() {
    let fw = firewall(CrossTenantReads::Observe);
    let response = to_http(read_a(&fw), axum::http::StatusCode::OK, "sess-1");
    let (_dir, log) = failing_log();
    let (refused, written) = emit_http_checked(response, Some(&log)).await;
    assert!(!written, "a refused answer was reported as written");
    assert_eq!(
        refused.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        refused
            .headers()
            .get("mcp-session-id")
            .map(axum::http::HeaderValue::as_bytes),
        Some(&b"sess-1"[..]),
        "the refusal keeps the session header"
    );
    let body = body_json(refused).await;
    assert_eq!(body["id"], json!(1));
    assert_eq!(
        body["error"]["code"],
        json!(crate::Error::AuditUnavailable.to_rpc_code())
    );
    assert!(
        body.get("result").is_none(),
        "the refusal carries no result"
    );

    // Control: the same answer with a healthy log goes out as built.
    let response = to_http(read_a(&fw), axum::http::StatusCode::OK, "sess-1");
    let (_dir, healthy) = logger(AuditFailurePolicy::FailClosed);
    let (sent, written) = emit_http_checked(response, Some(&healthy)).await;
    assert!(written);
    assert_eq!(sent.status(), axum::http::StatusCode::OK);
}

/// An id-less answer whose pending record fails is refused with a null id,
/// and no session header is invented. Mutant: the `None` id arm of
/// `emit_pending` removed.
#[tokio::test]
async fn a_failed_pending_record_refuses_an_idless_http_answer_with_a_null_id() {
    let fw = firewall(CrossTenantReads::Observe);
    let response = to_http(idless_answer_a(&fw), axum::http::StatusCode::OK, "");
    let (_dir, log) = failing_log();
    let (refused, written) = emit_http_checked(response, Some(&log)).await;
    assert!(!written);
    assert_eq!(
        refused.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(refused.headers().get("mcp-session-id").is_none());
    let body = body_json(refused).await;
    assert_eq!(body["id"], Value::Null);
    assert_eq!(
        body["error"]["code"],
        json!(crate::Error::AuditUnavailable.to_rpc_code())
    );
}
