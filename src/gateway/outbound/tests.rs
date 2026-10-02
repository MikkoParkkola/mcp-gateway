// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-7116.MIN.2 red tests at the judge: 2x (the scan covers the whole
//! emitted document, not an allow-list of fields) and F4 (the rejection
//! audit is admitted by a bounded permit).
//!
//! Each 2x row reads A first and keeps that frame unwritten, so its
//! reservation is live when B is judged. Each row runs its B frame with the
//! mode `off` as a control, so "B blocked" cannot pass vacuously.

use serde_json::{Value, json};

use super::*;
use crate::protocol::RequestId;
use crate::security::firewall::Firewall;
use crate::security::firewall::FirewallConfig;
use crate::security::firewall::tenant_guard::{CrossTenantReads, TenantGuardConfig};
use crate::security::hash_argument;
use crate::security::tenant_reads::RejectionEvidence;

const A: &str = "cust-a";
const B: &str = "cust-b";
const KEY: &str = "api_key:one";

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

/// An answer to a call that named A in its arguments.
fn read_a(fw: &Firewall) -> OutboundFrame {
    let answer = JsonRpcResponse::success(
        RequestId::Number(1),
        json!({ "content": [{ "type": "text", "text": "ok" }] }),
    );
    delivered(
        fw,
        Some(KEY),
        Payload::Response(answer),
        Some(&json!({ "customer_id": A })),
        None,
    )
}

fn names_b() -> String {
    json!({ "customer_id": B }).to_string()
}

/// Under `off`, B passes unjudged; under `block`, after A, it is withheld;
/// under `observe`, after A, it is delivered and flagged.
fn assert_b_judged(what: &str, b: impl Fn() -> Payload) {
    let off = firewall(CrossTenantReads::Off);
    let _a = read_a(&off);
    match admit(&off, Some(KEY), b(), None) {
        Admission::Admitted(frame) => assert_eq!(frame.verdict(), None, "control: off, {what}"),
        Admission::Blocked(e) => panic!("control: off never blocks {what}: {e:?}"),
    }

    let block = firewall(CrossTenantReads::Block);
    let _a = read_a(&block);
    match admit(&block, Some(KEY), b(), None) {
        Admission::Blocked(evidence) => {
            assert_eq!(evidence.verdict, ReadVerdict::Blocked, "{what}");
            assert!(
                evidence
                    .attribution
                    .tenants
                    .contains(&hash_argument(&json!(B))),
                "{what}: the evidence names h(B): {evidence:?}"
            );
        }
        Admission::Admitted(frame) => {
            panic!("{what} after an A read was admitted under block: {frame:?}")
        }
    }

    let observe = firewall(CrossTenantReads::Observe);
    let _a = read_a(&observe);
    match admit(&observe, Some(KEY), b(), None) {
        Admission::Admitted(frame) => assert_eq!(
            frame.verdict(),
            Some(ReadVerdict::Flagged),
            "{what} after an A read is flagged under observe"
        ),
        Admission::Blocked(e) => panic!("observe never withholds {what}: {e:?}"),
    }
}

/// 2x: B only in a backend notification's `method` string.
#[test]
fn scan_root_covers_the_notification_method() {
    assert_b_judged("a notification whose method names B", || {
        Payload::Notification(JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: names_b(),
            params: None,
        })
    });
}

/// 2x: B only inside a `proxy_request` sampling envelope.
#[test]
fn scan_root_covers_the_proxy_request_envelope() {
    assert_b_judged("a sampling request naming B", || {
        Payload::Request(json!({
            "jsonrpc": "2.0",
            "id": "gw-proxy-1",
            "method": "sampling/createMessage",
            "params": { "messages": [{
                "role": "user",
                "content": { "type": "text", "text": names_b() },
            }]},
        }))
    });
}

/// 2x: B only in a non-JSON-RPC SSE document (a webhook body).
#[test]
fn scan_root_covers_an_event_document() {
    assert_b_judged("a webhook event naming B", || {
        Payload::Event(json!({ "source": "hook", "data": { "customer_id": B } }))
    });
}

/// 2x, event half: B only in the event body before the event firewall's
/// redaction. The outbox carries the pre-redaction attribution; the
/// delivered body no longer names B.
#[test]
fn scan_root_covers_a_redacted_callback_body() {
    let raw = json!({ "type": "ticket.updated", "data": { "customer_id": B, "note": "x" } });
    let redacted = json!({ "type": "ticket.updated", "data": { "note": "x" } });

    let off = firewall(CrossTenantReads::Off);
    let _a = read_a(&off);
    let carried = attribute(&off, &raw);
    assert!(
        matches!(
            callback_frame(Some(&off), Some(KEY), redacted.clone(), Some(&carried)),
            Admission::Admitted(_)
        ),
        "control: off delivers the event"
    );

    let block = firewall(CrossTenantReads::Block);
    let carried = attribute(&block, &raw);
    assert!(
        carried.tenants.contains(&hash_argument(&json!(B))),
        "attribution is taken from the raw event: {carried:?}"
    );
    let _a = read_a(&block);
    assert!(
        matches!(
            callback_frame(Some(&block), Some(KEY), redacted, Some(&carried)),
            Admission::Blocked(_)
        ),
        "an event naming B before redaction, after an A read, must dead-letter"
    );
}

fn evidence() -> RejectionEvidence {
    RejectionEvidence {
        caller_key: Some(KEY.to_string()),
        verdict: ReadVerdict::Blocked,
        attribution: ReadAttribution {
            tenants: [hash_argument(&Value::String(B.to_string()))].into(),
            uninspected: false,
        },
    }
}

/// F4: a flood of rejected notifications spawns at most the permit count of
/// audit tasks; the rest are recorded as saturation. On a current-thread
/// runtime no spawned task runs before the loop ends, so every permit taken
/// is still held.
#[tokio::test]
async fn rejection_audit_admission_bounded() {
    let audit = RejectionAudit::new(None, 4);
    let spawned = (0..100).filter(|_| audit.submit(evidence())).count();
    assert!(
        spawned <= 4,
        "{spawned} audit tasks spawned for 100 rejections with 4 permits"
    );
    assert_eq!(
        audit.saturated(),
        u64::try_from(100 - spawned).unwrap(),
        "every rejection without a permit is a recorded audit failure"
    );
}

/// Row 7: a refused B request, then A: the refusal is not a read of B, so A
/// is ordinary. Control: a delivered B answer then A is flagged.
#[test]
fn gateway_refusal_charges_nothing() {
    let fw = firewall(CrossTenantReads::Observe);
    let refusal = JsonRpcResponse::error(Some(RequestId::Number(1)), -32600, "refused");
    let b = delivered(
        &fw,
        Some(KEY),
        Payload::Response(refusal),
        Some(&json!({ "customer_id": B })),
        None,
    );
    b.written();
    drop(b);
    assert_eq!(read_a(&fw).verdict(), None, "a refused B charged B");

    let fw = firewall(CrossTenantReads::Observe);
    let answer = JsonRpcResponse::success(RequestId::Number(1), json!({ "ok": true }));
    let _b = delivered(
        &fw,
        Some(KEY),
        Payload::Response(answer),
        Some(&json!({ "customer_id": B })),
        None,
    );
    assert_eq!(
        read_a(&fw).verdict(),
        Some(ReadVerdict::Flagged),
        "control: a delivered B answer is a read of B"
    );
}

/// Row 9 / review F6: a refusal that replaced backend content at
/// finalization charges nothing for the content it withheld.
#[test]
fn a_refusal_keeps_no_hidden_reading() {
    let fw = firewall(CrossTenantReads::Observe);
    let hidden = ReadAttribution {
        tenants: [hash_argument(&json!(B))].into(),
        uninspected: false,
    };
    let refusal = JsonRpcResponse::error(Some(RequestId::Number(1)), -32600, "blocked");
    let b = delivered(
        &fw,
        Some(KEY),
        Payload::Response(refusal),
        None,
        Some(&hidden),
    );
    b.written();
    drop(b);
    assert_eq!(
        read_a(&fw).verdict(),
        None,
        "a refusal charged its hidden B"
    );
}

/// A callback frame naming A for `KEY`, admitted under observe.
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

/// Whether a B answer for `KEY` is flagged now.
fn b_flagged(fw: &Firewall) -> bool {
    let answer = JsonRpcResponse::success(RequestId::Number(9), json!({ "customer_id": B }));
    delivered(fw, Some(KEY), Payload::Response(answer), None, None).verdict()
        == Some(ReadVerdict::Flagged)
}

/// 2y: a callback commits once its body is handed over, whatever the answer;
/// a send that never left the process releases it; a send cancelled in
/// flight commits (review finding 4).
#[tokio::test]
async fn callback_commits_at_send() {
    let fw = firewall(CrossTenantReads::Observe);
    let sent = send_callback(callback_a(&fw), KEY, |_body| async {
        CallbackSend::<()>::Sent(Err(crate::events::CallbackFailure::ConnectionRefused))
    })
    .await;
    assert!(sent.is_err(), "premise: the recipient failed after reading");
    assert!(
        b_flagged(&fw),
        "a body handed over commits, whatever the answer"
    );

    let fw = firewall(CrossTenantReads::Observe);
    let _ = send_callback(callback_a(&fw), KEY, |_body| async {
        CallbackSend::<()>::NotSent(crate::events::CallbackFailure::ConnectionRefused)
    })
    .await;
    assert!(!b_flagged(&fw), "nothing left the process: released");

    let fw = firewall(CrossTenantReads::Observe);
    let cancelled = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        send_callback(callback_a(&fw), KEY, |_body| async {
            std::future::pending::<CallbackSend<()>>().await
        }),
    )
    .await;
    assert!(
        cancelled.is_err(),
        "premise: the send was cancelled in flight"
    );
    assert!(b_flagged(&fw), "a send cancelled in flight still commits");
}
