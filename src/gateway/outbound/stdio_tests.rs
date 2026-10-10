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
        StdioReads::new(Some(Arc::new(firewall)), Arc::clone(&audit), None),
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

    let (block, _) = reads(CrossTenantReads::Block);
    let _a = read_a(&block).await;
    assert!(
        block.request(request_naming_b()).await.is_none(),
        "a bridged request naming B after an A read is withheld under block"
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
