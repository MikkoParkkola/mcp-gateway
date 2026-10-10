// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8195 W8: the stdio read judge's refusal branches. Each row reads A
//! first through the judge and keeps that frame unwritten, so its
//! reservation is live when B is judged, and runs the same B under `off` as
//! a control, so "withheld" cannot pass vacuously.

use std::sync::Arc;

use serde_json::{Value, json};

use super::*;
use crate::security::firewall::tenant_guard::{CrossTenantReads, TenantGuardConfig};
use crate::security::firewall::{Firewall, FirewallConfig};

const A: &str = "cust-a";
const B: &str = "cust-b";

/// A judge under `mode` whose rejection audit has no permits, so every
/// submitted rejection is counted as saturation and is observable.
fn reads(mode: CrossTenantReads) -> (StdioReads, Arc<RejectionAudit>) {
    reads_logged(mode, None)
}

/// [`reads`] writing its records to `log`.
fn reads_logged(
    mode: CrossTenantReads,
    log: Option<Arc<TransparencyLogger>>,
) -> (StdioReads, Arc<RejectionAudit>) {
    let firewall = Firewall::from_config(
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
    );
    let audit = Arc::new(RejectionAudit::new(None, 0));
    (
        StdioReads::new(Some(Arc::new(firewall)), Arc::clone(&audit), log),
        audit,
    )
}

/// An answer to a call that named A, judged and kept unwritten.
async fn read_a(reads: &StdioReads) -> OutboundFrame {
    let answer = json!({"jsonrpc": "2.0", "id": 1,
                        "result": {"content": [{"type": "text", "text": "ok"}]}});
    reads
        .answer(answer, Some(&json!({ "customer_id": A })), None)
        .await
}

fn names_b() -> String {
    json!({ "customer_id": B }).to_string()
}

fn note_naming_b() -> JsonRpcNotification {
    JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: names_b(),
        params: None,
    }
}

fn request_naming_b() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "gw-proxy-1",
        "method": "sampling/createMessage",
        "params": {"messages": [{
            "role": "user",
            "content": {"type": "text", "text": names_b()},
        }]},
    })
}

#[tokio::test]
async fn a_notification_naming_another_tenant_is_withheld_and_audited() {
    let (off, _) = reads(CrossTenantReads::Off);
    let _a = read_a(&off).await;
    assert!(
        off.notification(note_naming_b()).await.is_some(),
        "control: off delivers B"
    );

    let (block, audit) = reads(CrossTenantReads::Block);
    let _a = read_a(&block).await;
    assert!(
        block.notification(note_naming_b()).await.is_none(),
        "B after an A read is withheld under block"
    );
    assert_eq!(audit.saturated(), 1, "the rejection reached the audit");
}

#[tokio::test]
async fn a_bridged_request_naming_another_tenant_is_withheld() {
    let (off, _) = reads(CrossTenantReads::Off);
    let _a = read_a(&off).await;
    assert!(
        off.request(request_naming_b()).await.is_some(),
        "control: off forwards B"
    );

    // Without a transparency log the blocked request is still withheld; it
    // simply has nowhere to be audited.
    let (unlogged, _) = reads(CrossTenantReads::Block);
    let _a = read_a(&unlogged).await;
    assert!(
        unlogged.request(request_naming_b()).await.is_none(),
        "with no log, a bridged request naming B after an A read is still withheld"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let log = TransparencyLogger::open(Arc::new(
        crate::security::transparency_log::TransparencyLogConfig {
            enabled: true,
            path: path.to_string_lossy().into_owned(),
            key_id: "w8".to_string(),
            ..Default::default()
        },
    ))
    .expect("open log");
    let (block, _) = reads_logged(CrossTenantReads::Block, Some(Arc::new(log)));
    let _a = read_a(&block).await;
    assert!(
        block.request(request_naming_b()).await.is_none(),
        "a bridged request naming B after an A read is withheld under block"
    );
    let records = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        records
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .any(
                |r| r.pointer("/cross_tenant_read") == Some(&json!("blocked"))
                    || r.pointer("/fields/cross_tenant_read") == Some(&json!("blocked"))
            ),
        "the withheld request's rejection is in the transparency log: {records}"
    );
}

/// An answer is replaced, not withheld: the request still gets a reply, a
/// refusal that carries none of B's content.
#[test]
fn a_finalized_answer_naming_another_tenant_is_replaced_by_a_refusal() {
    let answer_b = || {
        crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(2),
            json!({"content": [{"type": "text", "text": names_b()}]}),
        )
    };
    let written = |reads: &StdioReads| {
        reads
            .judge(answer_b(), None, None)
            .stdio_value()
            .map(Cow::into_owned)
            .expect("an answer always writes a reply")
    };
    let (off, _) = reads(CrossTenantReads::Off);
    let _a = futures::executor::block_on(read_a(&off));
    let delivered = written(&off);
    assert!(
        delivered.to_string().contains(B),
        "control: off delivers B: {delivered}"
    );

    let (block, _) = reads(CrossTenantReads::Block);
    let _a = futures::executor::block_on(read_a(&block));
    let refused = written(&block);
    assert!(
        refused.get("error").is_some(),
        "block answers with a refusal: {refused}"
    );
    assert!(refused.get("result").is_none(), "{refused}");
    assert!(
        !refused.to_string().contains(B),
        "the refusal carries none of B: {refused}"
    );
}

#[test]
fn a_withheld_frame_writes_nothing_and_a_batch_drops_it() {
    assert!(
        OutboundFrame::unjudged(Payload::Withheld)
            .stdio_value()
            .is_none()
    );
    let batch = StdioReads::batch_of(vec![
        OutboundFrame::unjudged(Payload::Withheld),
        OutboundFrame::gateway_stdio(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
    ]);
    assert_eq!(
        batch.stdio_value().map(Cow::into_owned),
        Some(json!([{"jsonrpc": "2.0", "id": 1, "result": {}}]))
    );
}
