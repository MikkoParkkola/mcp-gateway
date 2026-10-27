// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8697 §16.14: one row per `tenant_read` writer path. Each drives the
//! functions that path calls in production and asserts the logged
//! `caller_key`: a credential key is written keyed (`credential:rp:<12 hex>`)
//! and the raw principal appears nowhere in the record, while the key the
//! guard judged under stays raw in process. The stdio key names the
//! transport, not a credential, and is written as it is.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::{Value, json};
use tempfile::TempDir;

use super::*;
use crate::protocol::RequestId;
use crate::security::firewall::tenant_guard::{CrossTenantReads, TenantGuardConfig};
use crate::security::firewall::{Firewall, FirewallConfig};
use crate::security::tenant_reads::{ReadAttribution, ReadVerdict, RejectionEvidence};
use crate::security::{TransparencyLogConfig, TransparencyLogger};

/// The stored principal a credential caller key embeds.
const RAW: &str = "3f2a9c0d1e7b";
/// A credential caller key, as `router::identity::caller_key` builds it.
const CRED: &str = "credential:12:3f2a9c0d1e7b";

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

/// A log in a fresh directory; a logger opened in test code starts keyed
/// with the test record key.
fn logger() -> (TempDir, Arc<TransparencyLogger>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: dir.path().join("transparency.ndjson").display().to_string(),
        ..TransparencyLogConfig::default()
    }))
    .expect("log");
    (dir, Arc::new(log))
}

/// Every record carrying a `caller_key`.
fn keyed_records(dir: &TempDir) -> Vec<Value> {
    std::fs::read_to_string(dir.path().join("transparency.ndjson"))
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|record| record.get("caller_key").is_some())
        .collect()
}

/// `count` records, each with `caller_key` keyed and no trace of [`RAW`].
#[track_caller]
fn assert_keyed(dir: &TempDir, count: usize) {
    let records = keyed_records(dir);
    assert_eq!(records.len(), count, "{records:#?}");
    let want = format!(
        "credential:rp:{}",
        crate::gateway::record_principal::InternalPrincipal::new(RAW.to_owned())
            .record_form(&crate::gateway::record_principal::test_record_key())
            .as_str()
    );
    for record in &records {
        assert_eq!(record["caller_key"], want.as_str(), "{record}");
        assert!(!record.to_string().contains(RAW), "{record}");
    }
}

fn answer_naming(tenant: &str) -> Payload {
    Payload::Response(JsonRpcResponse::success(
        RequestId::Number(1),
        json!({ "customer_id": tenant }),
    ))
}

/// Outbound: an answer's standalone record (`recorded`, the meta route and
/// HTTP `emit_http` path).
#[tokio::test]
async fn ck_outbound_an_answer_record_logs_the_caller_key_keyed() {
    let fw = firewall(CrossTenantReads::Observe);
    let (dir, log) = logger();
    let frame = delivered(&fw, Some(CRED), answer_naming("cust-a"), None, None);
    assert_eq!(frame.key.as_deref(), Some(CRED), "judged under the raw key");
    let frame = recorded(frame, Some(&log)).await;
    assert!(!frame.is_withheld());
    assert_keyed(&dir, 1);
}

/// `audit_rejection`: the record of a withheld frame.
#[tokio::test]
async fn ck_rejection_a_withheld_frame_record_logs_the_caller_key_keyed() {
    let (dir, log) = logger();
    let evidence = RejectionEvidence {
        caller_key: Some(CRED.to_owned()),
        verdict: ReadVerdict::Blocked,
        attribution: ReadAttribution::of(BTreeSet::from(["cust-b".to_owned()]), false),
    };
    audit::audit_rejection(&log, &evidence).await;
    assert_keyed(&dir, 1);
}

/// The events worker (`worker.rs` `admit_delivery`): `callback_frame` then
/// `recorded` when admitted, `audit_rejection` when blocked.
#[tokio::test]
async fn ck_events_worker_callback_records_log_the_caller_key_keyed() {
    let fw = firewall(CrossTenantReads::Block);
    let (dir, log) = logger();
    let read_a = attribute(&fw, &json!({ "customer_id": "cust-a" }));
    let Admission::Admitted(frame) =
        callback_frame(Some(&fw), Some(CRED), json!({ "data": {} }), Some(&read_a))
    else {
        panic!("a first read is admitted");
    };
    // Held, as the worker holds it until sent: its reservation stays live.
    let held_a = recorded(frame, Some(&log)).await;
    assert!(!held_a.is_withheld());
    let read_b = attribute(&fw, &json!({ "customer_id": "cust-b" }));
    let Admission::Blocked(evidence) =
        callback_frame(Some(&fw), Some(CRED), json!({ "data": {} }), Some(&read_b))
    else {
        panic!("a second tenant in the window is blocked");
    };
    assert_eq!(evidence.caller_key.as_deref(), Some(CRED), "judged raw");
    audit::audit_rejection(&log, &evidence).await;
    drop(held_a);
    assert_keyed(&dir, 2);
}

/// The delivery merge: an answer's read fields ride its delivery record
/// (`record_answer_delivery`, the direct route; the meta route merges the
/// same way).
#[tokio::test]
async fn ck_delivery_merge_logs_the_caller_key_keyed() {
    let fw = firewall(CrossTenantReads::Observe);
    let (dir, log) = logger();
    let mut frame = delivered(&fw, Some(CRED), answer_naming("cust-a"), None, None);
    let read = frame.take_record_fields();
    assert!(read.is_some(), "the answer was judged");
    let correlation = crate::security::response_policy::ResponseCorrelation {
        session_id: "",
        caller: "alpha-client",
        external_server: "alpha",
        external_tool: "read",
        subject: None,
        trace_id: None,
        key: crate::security::response_policy::KeyOf::NotKnown,
    };
    let logged = crate::gateway::meta_mcp::response_security::record_answer_delivery(
        Some(&log),
        Ok(json!({ "jsonrpc": "2.0", "id": 1, "result": {} })),
        crate::security::audit::AuditOutcome::Ok,
        &correlation,
        crate::gateway::meta_mcp::response_security::DeliveryCredential {
            kind: crate::security::audit::CredentialKind::ApiKey,
            principal: crate::gateway::record_principal::RecordPrincipal::none(),
        },
        read,
    )
    .await;
    assert!(logged);
    assert_keyed(&dir, 1);
}

/// Stdio: every frame is judged for `STDIO_KEY`, the transport and not a
/// credential, so the record carries it as it is and nothing to key.
#[tokio::test]
async fn ck_stdio_records_the_transport_key_as_it_is() {
    let (dir, log) = logger();
    let reads = StdioReads::new(
        Some(Arc::new(firewall(CrossTenantReads::Observe))),
        Arc::new(RejectionAudit::new(None, 0)),
        Some(Arc::clone(&log)),
    );
    let answer = json!({ "jsonrpc": "2.0", "id": 1, "result": {} });
    let frame = reads
        .answer(answer, Some(&json!({ "customer_id": "cust-a" })), None)
        .await;
    assert!(!frame.is_withheld());
    let records = keyed_records(&dir);
    assert_eq!(records.len(), 1, "{records:#?}");
    assert_eq!(records[0]["caller_key"], stdio::STDIO_KEY, "{}", records[0]);
}
