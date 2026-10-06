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

/// A tenant id the event firewall redacted is the tenant the record's
/// attribution names, not a second tenant named by the marker that replaced it.
#[test]
fn a_redacted_tenant_field_does_not_name_a_second_tenant() {
    let raw = json!({ "data": { "customer_id": A } });
    let redacted = json!({ "data": { "customer_id": "[REDACTED:credential]" } });
    let block = firewall(CrossTenantReads::Block);
    let carried = attribute(&block, &raw);
    assert!(
        matches!(
            callback_frame(Some(&block), Some(KEY), redacted, Some(&carried)),
            Admission::Admitted(_)
        ),
        "a first, single-tenant delivery is not blocked by its own redaction marker"
    );
}

/// A configured key at the envelope root names a tenant: excluding `data`
/// from the scan must not drop the envelope's own member names.
#[test]
fn a_tenant_key_at_the_callback_envelope_root_is_scanned() {
    let block = firewall(CrossTenantReads::Block);
    let _a = read_a(&block);
    let envelope = json!({ "customer_id": B, "data": { "note": "x" } });
    assert!(
        matches!(
            callback_frame(Some(&block), Some(KEY), envelope, None),
            Admission::Blocked(_)
        ),
        "an envelope naming B after an A read is withheld"
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

/// MIK-7887: a stdio answer whose `result` is `null` delivers a result, as a
/// typed response and the judge's own reading do; an error-only answer does not.
#[test]
fn a_null_result_answer_delivers_a_result() {
    let frame = |v: Value| OutboundFrame::gateway_stdio(v);
    assert!(frame(json!({"jsonrpc": "2.0", "id": 1, "result": null})).delivers_result());
    assert!(frame(json!({"jsonrpc": "2.0", "id": 1, "result": {}})).delivers_result());
    assert!(
        !frame(json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "x"}}))
            .delivers_result()
    );
}

/// MIK-7778: stored task output carries no attribution, so each such document
/// is a read that cannot be attributed to a tenant. Under `block` a second one
/// for the same caller is withheld; the same neutral document judged as an
/// ordinary frame is not, so the assertion cannot pass vacuously.
#[tokio::test]
async fn a_restored_task_document_is_an_unattributed_read() {
    let judge = |mode| {
        let judge = StreamJudge::new(
            Some(std::sync::Arc::new(firewall(mode))),
            std::sync::Arc::new(RejectionAudit::new(None, 1)),
            None,
        );
        judge.bind(KEY.to_owned());
        judge
    };
    let neutral = || json!({ "jsonrpc": "2.0", "method": "notifications/tasks", "params": { "taskId": "t" } });

    let ordinary = judge(CrossTenantReads::Block);
    assert!(ordinary.judge_document(neutral()).is_some(), "control");
    assert!(
        ordinary.judge_document(neutral()).is_some(),
        "control: a neutral document names no tenant"
    );

    let restored = judge(CrossTenantReads::Block);
    // Kept unwritten, so its reservation is live when the second is judged.
    let first = restored.judge_restored_document(neutral());
    assert!(first.is_some());
    assert!(
        restored.judge_restored_document(neutral()).is_none(),
        "a second unattributed read for one caller is withheld under block"
    );
    drop(first);
}

/// A firewall judging `keys` instead of the default `customer_id`.
fn firewall_with(mode: CrossTenantReads, keys: &[&str]) -> Firewall {
    Firewall::from_config(
        FirewallConfig {
            tenant_guard: TenantGuardConfig {
                enabled: false,
                window_secs: 3600,
                arg_keys: keys.iter().map(|k| (*k).to_string()).collect(),
                cross_tenant_reads: mode,
                ..TenantGuardConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    )
}

/// MIK-7883.SCAN.2: the scan reads the emitted document with its member
/// names, not pieces. A configured key equal to a wrapper member that names
/// another tenant is attributed and, under `block`, withheld: the `message` of
/// a JSON-RPC error.
#[test]
fn the_message_member_of_an_error_is_scanned() {
    let fw = firewall_with(CrossTenantReads::Block, &["customer_id", "message"]);
    let _a = read_a(&fw);
    let refused = JsonRpcResponse::error(Some(RequestId::Number(2)), -32000, B);
    let frame = delivered(&fw, Some(KEY), Payload::Response(refused), None, None);
    assert_eq!(frame.verdict(), Some(ReadVerdict::Blocked));
}

/// MIK-7883.SCAN.2: `error.data` judged under a wrapper `arg_keys` entry. A
/// configured key equal to the envelope member `data` matches the error's own
/// `data`, whether it holds the tenant directly or wraps it, so a refusal that
/// carries another tenant in its data is withheld like any other frame. The
/// bare scalar is the load-bearing case: only the emitted-document scan sees
/// it under the member name `data`. The owner's own tenant in the same place
/// is admitted, so blocking every `error.data` cannot pass.
#[test]
fn the_data_member_of_an_error_is_scanned() {
    let fw = firewall_with(CrossTenantReads::Block, &["customer_id", "data"]);
    let _a = read_a(&fw);
    let refusal = |data: &serde_json::Value| {
        let refused = JsonRpcResponse::error_with_data(
            Some(RequestId::Number(2)),
            -32000,
            "refused",
            data.clone(),
        );
        delivered(&fw, Some(KEY), Payload::Response(refused), None, None)
    };
    for data in [json!(B), json!({ "data": B })] {
        assert_eq!(
            refusal(&data).verdict(),
            Some(ReadVerdict::Blocked),
            "{data}"
        );
    }
    for data in [json!(A), json!({ "data": A })] {
        assert_eq!(refusal(&data).verdict(), None, "the owner's own {data}");
    }
}

/// MIK-7883.SCAN.2: the `method` of a notification.
#[test]
fn the_method_member_of_a_notification_is_scanned() {
    let fw = firewall_with(CrossTenantReads::Block, &["customer_id", "method"]);
    let _a = read_a(&fw);
    let note = crate::protocol::JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: B.to_string(),
        params: None,
    };
    match admit(&fw, Some(KEY), Payload::Notification(note), None) {
        Admission::Blocked(evidence) => assert_eq!(evidence.verdict, ReadVerdict::Blocked),
        Admission::Admitted(frame) => panic!("a notification naming B was admitted: {frame:?}"),
    }
}

/// MIK-7883.SCAN.3, a proof-by-test pin (it passes before and after, so it is
/// not a red test): the serialized response is clamped, so a `cacheScope`
/// holding a tenant is scanned from the raw value, and the clamp's own `private`
/// is never attributed: the evidence is exactly the original tenant.
#[test]
fn a_clamped_cache_scope_cannot_hide_a_tenant() {
    let fw = firewall_with(CrossTenantReads::Block, &["customer_id", "cacheScope"]);
    let _a = read_a(&fw);
    for scope in [json!(B), json!({ "customer_id": B })] {
        let b = JsonRpcResponse::success(
            RequestId::Number(3),
            json!({ "content": [], "cacheScope": scope }),
        );
        let frame = delivered(&fw, Some(KEY), Payload::Response(b), None, None);
        assert_eq!(frame.verdict(), Some(ReadVerdict::Blocked), "{scope}");
        // Exactly B: the clamp's `private` is the gateway's own value, so it
        // is no evidence and names no tenant.
        let named = &frame.assessment().expect("judged").attribution.tenants;
        let only_b: std::collections::BTreeSet<_> = [hash_argument(&json!(B))].into();
        assert_eq!(named, &only_b, "{scope}");
    }
}

/// MIK-7883.SCAN.3 admission side: with `cacheScope` configured as a key, a
/// tenant reading its own value is admitted. The clamp's `private` would be a
/// second, unownable tenant and refuse the owner under `block`.
#[test]
fn a_tenants_own_cache_scope_is_admitted() {
    let fw = firewall_with(CrossTenantReads::Block, &["customer_id", "cacheScope"]);
    let _a = read_a(&fw);
    let own = JsonRpcResponse::success(
        RequestId::Number(4),
        json!({ "content": [], "cacheScope": A }),
    );
    let frame = delivered(&fw, Some(KEY), Payload::Response(own), None, None);
    assert_eq!(frame.verdict(), None, "the owner's own value is admitted");
}

/// MIK-7883.SCAN.4: every payload variant has a scan row. The exhaustive
/// match fails to compile when a variant is added, and each value-document
/// row is exercised: a configured key at the document's top level naming B is
/// attributed.
#[test]
fn every_payload_variant_has_a_scan_row() {
    let doc = || json!({ "customer_id": B });
    for payload in [
        Payload::Answer(doc()),
        Payload::Request(doc()),
        Payload::Event(doc()),
        Payload::Callback(doc()),
    ] {
        let fw = firewall(CrossTenantReads::Block);
        let _a = read_a(&fw);
        match admit(&fw, Some(KEY), payload, None) {
            Admission::Blocked(_) => {}
            Admission::Admitted(frame) => panic!("a payload naming B was admitted: {frame:?}"),
        }
    }
    // The tripwire: a new `Payload` variant must be placed in a row here.
    let classify = |p: &Payload| match p {
        Payload::Response(_) | Payload::Notification(_) => "serialized document (SCAN.2)",
        Payload::Answer(_) | Payload::Request(_) | Payload::Event(_) | Payload::Callback(_) => {
            "value document"
        }
        Payload::Batch(_) => "items judged one by one",
        Payload::Withheld => "nothing emitted",
    };
    assert_eq!(classify(&Payload::Withheld), "nothing emitted");
}

/// MIK-7924.NULLRES.4: a backend's `"result": null`, parsed as a typed
/// response, is a delivered result to the frame and to the judge alike. The
/// judge shows it by charging the call's A, so a later B is flagged; the
/// control charges nothing, so the flag is not vacuous.
#[test]
fn a_typed_null_result_delivers_to_the_frame_and_the_judge() {
    let control = firewall(CrossTenantReads::Observe);
    assert!(!b_flagged(&control), "control: B alone is not flagged");

    let fw = firewall(CrossTenantReads::Observe);
    let typed: JsonRpcResponse =
        serde_json::from_value(json!({"jsonrpc": "2.0", "id": 1, "result": null}))
            .expect("a response");
    let frame = delivered(
        &fw,
        Some(KEY),
        Payload::Response(typed),
        Some(&json!({ "customer_id": A })),
        None,
    );
    // The A frame stays unwritten, so its reservation is live when B is judged.
    assert!(b_flagged(&fw), "the judge charged the call's A");
    assert!(
        frame.delivers_result(),
        "the frame delivers the null result"
    );
}

/// A non-message session-stream item judged for `KEY`: its `data` and the
/// whole tagged notification it is written as.
fn stream_item(fw: &Firewall, data: Value, source: &str) -> Admission {
    let note = crate::gateway::streaming::TaggedNotification {
        source: source.to_string(),
        event_type: "progress".to_string(),
        data,
        event_id: Some("e-1".to_string()),
    };
    let wrapper = serde_json::to_value(&note).expect("a notification serializes");
    super::judge::admit_stream_item(
        fw,
        Some(KEY),
        &note.data,
        (note.event_type.as_str(), Some(&wrapper)),
        None,
    )
}

/// MIK-7942 D6.CATALOGUE.7: the stream item's `data` is scanned minus its
/// `jsonrpc` and `id`; the wrapper scan must not walk `data` again and read
/// that `id` back. Here `data.id` equals another tenant under a configured
/// `id` key: the item is admitted with nothing attributed.
#[test]
fn a_stream_wrapper_does_not_rescan_the_data_id() {
    let fw = firewall_with(CrossTenantReads::Block, &["customer_id", "id"]);
    let _a = read_a(&fw);
    let data = json!({ "jsonrpc": "2.0", "id": B, "method": "m" });
    match stream_item(&fw, data, "gateway") {
        Admission::Admitted(frame) => {
            assert_eq!(frame.verdict(), None);
            let named = frame.assessment().map(|a| a.attribution.tenants.clone());
            assert!(
                named.unwrap_or_default().is_empty(),
                "nothing is attributed"
            );
        }
        Admission::Blocked(e) => panic!("data.id was attributed: {e:?}"),
    }
}

/// MIK-7942 D6.CATALOGUE.8 pin (green before and after): the response judge
/// scans placeholders for `result`, so a configured key equal to `result`
/// must still match a scalar result naming another tenant.
#[test]
fn a_scalar_result_under_a_result_key_is_attributed() {
    let fw = firewall_with(CrossTenantReads::Block, &["customer_id", "result"]);
    let _a = read_a(&fw);
    let b = JsonRpcResponse::success(RequestId::Number(5), json!(B));
    let frame = delivered(&fw, Some(KEY), Payload::Response(b), None, None);
    assert_eq!(frame.verdict(), Some(ReadVerdict::Blocked));
}

/// MIK-7942 D6.CATALOGUE.7 pins (green before and after the fix): the wrapper
/// still matches a configured key equal to `data` against a scalar `data`,
/// and its own members (`source`) are still scanned.
#[test]
fn a_stream_wrapper_still_matches_its_own_members() {
    for data in [json!(B), json!(7)] {
        let fw = firewall_with(CrossTenantReads::Block, &["customer_id", "data"]);
        let _a = read_a(&fw);
        // A string or a number names a tenant other than A.
        match stream_item(&fw, data.clone(), "gateway") {
            Admission::Blocked(_) => {}
            Admission::Admitted(frame) => panic!("a scalar data {data} was missed: {frame:?}"),
        }
    }
    let fw = firewall_with(CrossTenantReads::Block, &["customer_id", "source"]);
    let _a = read_a(&fw);
    match stream_item(&fw, json!({ "note": "n" }), B) {
        Admission::Blocked(_) => {}
        Admission::Admitted(frame) => panic!("a source naming B was admitted: {frame:?}"),
    }
}
