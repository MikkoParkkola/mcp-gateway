// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The cross-tenant read verdict on stdio, through the staged dispatch and
//! `judge_and_commit` the stdio loop runs, with the judge from
//! `MetaMcp::stdio_reads`. With the firewall on, the outcomes match the HTTP
//! rows' (`router::tests::meta_firewall_verdict::caller_key::tenant_reads`):
//! `block` refuses B after A, `observe` delivers and flags it. With the
//! firewall off the outcomes are the same: the verdict runs on its own switch.

use super::*;
use crate::gateway::outbound::{OutboundFrame, StdioReads};
use crate::security::TransparencyLogger;
use crate::security::firewall::tenant_guard::{CrossTenantReads, TenantGuardConfig};
use crate::security::firewall::{Firewall, FirewallConfig};
use crate::security::transparency_log::TransparencyLogConfig;

const A: &str = "cust-a";
const B: &str = "cust-b";
const SESSION: &str = "stdio-read-verdict";

/// `security.firewall.enabled` for a row.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Switch {
    On,
    Off,
}

/// A stdio Meta-MCP with the verdict in `mode` on `customer_id` and the
/// firewall switch at `switch`, logging to `log_dir`.
async fn judged_meta(
    switch: Switch,
    mode: CrossTenantReads,
    log_dir: &Arc<tempfile::TempDir>,
) -> Arc<MetaMcp> {
    judged_meta_answering(switch, mode, log_dir, text_result("ok")).await
}

/// [`judged_meta`] whose backend answers every call with `answer`.
async fn judged_meta_answering(
    switch: Switch,
    mode: CrossTenantReads,
    log_dir: &Arc<tempfile::TempDir>,
    answer: Value,
) -> Arc<MetaMcp> {
    let firewall = Firewall::from_config(
        FirewallConfig {
            enabled: switch == Switch::On,
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
    let log = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: log_dir
            .path()
            .join("audit.jsonl")
            .to_string_lossy()
            .into_owned(),
        key_id: "stdio-reads".to_string(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log");
    // A late append lands before the directory goes.
    log.keep_test_dir(Arc::clone(log_dir));
    let transport = Arc::new(Counting {
        calls: Arc::new(AtomicUsize::new(0)),
        answer,
    });
    stdio_meta(
        |meta| {
            meta.set_firewall(Some(Arc::new(firewall)));
            meta.enable_transparency_log(Arc::new(log));
        },
        transport,
    )
    .await
}

/// One stdio `gateway_invoke alpha read` naming `tenant`, dispatched,
/// judged and written as the stdio loop does: stdout taking the frame
/// (`stdio_written`, `stdio_writer.rs`) is what commits the read.
async fn read(meta: &Arc<MetaMcp>, reads: &StdioReads, n: u64, tenant: &str) -> OutboundFrame {
    let request = json!({ "jsonrpc": "2.0", "id": n, "method": "tools/call",
        "params": invoke_read(&json!({ "customer_id": tenant })) });
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let line =
        crate::gateway::authz::test_line(meta, &crate::security::ToolPolicyConfig::default());
    let ((answer, staged), hidden) = crate::gateway::outbound::read_scoped(
        reads.guard(),
        Box::pin(super::super::Gateway::dispatch_single_staged(
            meta,
            &line,
            &mtls,
            request.clone(),
            super::super::StdioClient {
                session_id: SESSION,
                channel: &crate::gateway::input_bridge::NoClientChannel,
                handshake_capabilities: crate::protocol::meta::Declared::NONE,
                tasks: None,
                serving: super::super::stdio_single::ModernServing::Enabled,
                discover: super::super::stdio_single::DiscoverListing::Configured,
                sanitize: super::super::stdio_single::InputSanitizing::Off,
            },
        )),
    )
    .await;
    let answer = answer.expect("a request carrying an id is answered");
    let frame = super::super::Gateway::judge_and_commit(
        meta,
        reads,
        SESSION,
        (answer, request.get("params"), hidden.as_ref()),
        staged,
    )
    .await;
    frame.stdio_written();
    frame
}

/// The `cross_tenant_read` values on the log's delivery records, in order,
/// at the top level or one envelope down.
fn verdicts(log_dir: &tempfile::TempDir) -> Vec<String> {
    let field = |record: &Value, name: &str| -> Option<String> {
        let direct = record.get(name).and_then(Value::as_str);
        direct
            .or_else(|| {
                record
                    .as_object()?
                    .values()
                    .find_map(|inner| inner.get(name).and_then(Value::as_str))
            })
            .map(str::to_owned)
    };
    std::fs::read_to_string(log_dir.path().join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|r| field(r, "event").as_deref() == Some("response_delivery_attempt"))
        .filter_map(|r| field(&r, "cross_tenant_read"))
        .collect()
}

/// A then B on one stdio Meta-MCP: whether each delivers a result, and the
/// verdicts its delivery records carry.
pub(crate) async fn a_then_b(switch: Switch, mode: CrossTenantReads) -> ([bool; 2], Vec<String>) {
    let log_dir = crate::test_dir_keep::kept_tempdir();
    let meta = judged_meta(switch, mode, &log_dir).await;
    let reads = meta.stdio_reads();
    let a = read(&meta, &reads, 1, A).await.delivers_result();
    let b = read(&meta, &reads, 2, B).await.delivers_result();
    ([a, b], verdicts(&log_dir))
}

/// The HTTP rows' outcome for B after A in `mode`: refused under `block`,
/// delivered and flagged under `observe`, delivered unjudged under `off`.
fn http_outcome(mode: CrossTenantReads) -> ([bool; 2], Vec<String>) {
    match mode {
        CrossTenantReads::Block => ([true, false], vec!["blocked".to_string()]),
        CrossTenantReads::Observe => ([true, true], vec!["flagged".to_string()]),
        CrossTenantReads::Off => ([true, true], Vec::new()),
    }
}

/// Firewall on: stdio makes the HTTP verdict on the same A-then-B sequence.
#[tokio::test]
async fn stdio_makes_the_http_verdict() {
    for mode in [
        CrossTenantReads::Off,
        CrossTenantReads::Observe,
        CrossTenantReads::Block,
    ] {
        assert_eq!(
            a_then_b(Switch::On, mode).await,
            http_outcome(mode),
            "{mode:?}: stdio's outcome and verdicts"
        );
    }
}

/// Firewall off: stdio still judges, with the same outcomes.
#[tokio::test]
async fn stdio_judges_with_the_firewall_off() {
    for mode in [
        CrossTenantReads::Off,
        CrossTenantReads::Observe,
        CrossTenantReads::Block,
    ] {
        assert_eq!(
            a_then_b(Switch::Off, mode).await,
            http_outcome(mode),
            "{mode:?}: stdio's outcome and verdicts with the firewall off"
        );
    }
}

/// Attribution keeps running with the firewall off: a call whose answer
/// names A writes its invocation record with A's hashed tenant. The request
/// names another tenant, so A can come only from the answer's attribution.
#[tokio::test]
async fn the_invocation_record_names_tenants_with_the_firewall_off() {
    let log_dir = crate::test_dir_keep::kept_tempdir();
    let answer = text_result(&json!({ "customer_id": A }).to_string());
    let meta = judged_meta_answering(Switch::Off, CrossTenantReads::Off, &log_dir, answer).await;
    let reads = meta.stdio_reads();
    assert!(
        read(&meta, &reads, 1, "cust-request")
            .await
            .delivers_result(),
        "premise: the answer naming A is delivered"
    );
    let hashed = crate::security::hash_argument(&json!(A));
    let records: Vec<Value> = std::fs::read_to_string(log_dir.path().join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|r| r.get("tool").is_some())
        .collect();
    assert!(
        records.iter().any(|r| r
            .get("tenants")
            .and_then(Value::as_array)
            .is_some_and(|t| t.contains(&json!(hashed)))),
        "an invocation record carries A's hashed tenant, read from the answer: {records:#?}"
    );
}
