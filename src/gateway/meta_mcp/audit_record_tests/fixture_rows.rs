// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decision fixture table, meta-route refusal rows: one concrete call per
//! decider site, each pinning its whole decision with `assert_row`.
//!
//! What every refusal row pins, read at 01aa22f2cc:
//! - `rule_id` absent: each site below notes its kind with `None`.
//! - `grant_id` absent: the decision constructor sets `grant_id: None`
//!   (`decision_record.rs:304`) and nothing writes it; flipped when a writer of
//!   the decision's grant id lands.
//! - findings `NotRun`: no production writer of `request_findings` yet;
//!   flipped when the request-findings writer lands.
//! - no effect: an effect is noted only after admission.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::{Scripted, api_key_caller, context, ok_result, records};
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::visible::memo::with_visibility_memo;
use crate::security::decision_fixture_table::{DecisionRow, Findings, RuleId, assert_row};
use crate::security::transparency_log::TransparencyLogConfig;

/// `Scripted` that counts the `tools/call`s it answers.
struct Counted(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl crate::transport::Transport for Counted {
    async fn request(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method == "tools/call" {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        Scripted(Ok(ok_result())).request(method, params).await
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

/// One table gateway: backend `alpha` under `config`, logging to `dir`, and
/// the count of calls `alpha` was sent.
fn table_meta(dir: &tempfile::TempDir, config: BackendConfig) -> (MetaMcp, Arc<AtomicUsize>) {
    let sent = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Counted(Arc::clone(&sent))));
    let _ = registry.register(backend);
    let logger = crate::security::TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: dir.path().join("audit.jsonl").to_string_lossy().into_owned(),
        key_id: "d1".to_string(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log");
    let mut meta = MetaMcp::new(registry);
    meta.enable_transparency_log(Arc::new(logger));
    (meta, sent)
}

/// `server`'s `read`, invoked by an API-key caller inside one request memo:
/// the answer as the caller sees it (an error, or an `isError` result), and
/// the call's one decision. The record must show a refusal: an outcome other
/// than `ok`, with an error code.
async fn refused(meta: &MetaMcp, dir: &tempfile::TempDir, server: &str) -> (String, Value) {
    let who = api_key_caller();
    let args = json!({"server": server, "tool": "read", "arguments": {}});
    let answer =
        with_visibility_memo(meta.invoke_tool(&args, None, &context(&AllowAll, &who))).await;
    let answer = match answer {
        Ok(result) => {
            assert_eq!(result["isError"], true, "premise: the call is refused: {result}");
            result.to_string()
        }
        Err(error) => format!("{error:?}"),
    };
    let all = records(dir);
    let [record] = all.as_slice() else {
        panic!("premise: one invocation record: {all:?}; answer {answer}");
    };
    eprintln!("ROWPROBE {answer} || outcome={} code={} decision={}", record["outcome"], record["error_code"], record["decision"]);
    assert_ne!(record["outcome"], "ok", "{answer}: {record}");
    assert!(record["error_code"].is_i64(), "{answer}: {record}");
    (answer, record["decision"].clone())
}

/// A refusal row: `kind` at a kind-only site, nothing else recorded.
const fn refusal(name: &'static str, kind: &'static str) -> DecisionRow {
    DecisionRow {
        name,
        kind,
        rule_id: RuleId::Absent("kind-only site: noted with no rule id"),
        grant_id: None,
        findings: Findings::NotRun,
        effect: None,
        decided: "fresh",
    }
}

/// T1: the backend's `allowed_tools` leaves `read` out (`visible.rs:46`,
/// `Withholding::Unselected`, via `descriptor_gate.rs:305`).
#[tokio::test]
async fn t1_meta_allowed_tools() {
    let dir = tempfile::tempdir().expect("a log directory");
    let config = BackendConfig {
        allowed_tools: Some(vec!["write".to_string()]),
        ..BackendConfig::default()
    };
    let (meta, sent) = table_meta(&dir, config);
    let (error, decision) = refused(&meta, &dir, "alpha").await;
    assert_eq!(sent.load(Ordering::SeqCst), 0, "the backend was sent the call: {error}");
    assert_row(&decision, &refusal("t1_meta_allowed_tools", "allowed_tools"));
}

/// C1: a disabled capability (`dispatch_guards.rs:319`, in `admit_target`).
#[tokio::test]
async fn c1_meta_capability_disabled() {
    let dir = tempfile::tempdir().expect("a log directory");
    let (meta, sent) = table_meta(&dir, BackendConfig::default());
    let budget = crate::kill_switch::CapabilityErrorBudgetConfig::default();
    for _ in 0..20 {
        meta.kill_switch
            .record_capability_failure("alpha", "read", &budget);
    }
    assert!(
        meta.kill_switch.is_capability_disabled("alpha", "read"),
        "premise: the capability is disabled"
    );
    let (error, decision) = refused(&meta, &dir, "alpha").await;
    assert_eq!(sent.load(Ordering::SeqCst), 0, "the backend was sent the call: {error}");
    assert_row(&decision, &refusal("c1_meta_capability_disabled", "capability_disabled"));
}

/// The gateway's default routing profile leaves `read` out.
fn without_read(meta: MetaMcp) -> MetaMcp {
    use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
    let profiles = std::collections::HashMap::from([(
        "restricted".to_string(),
        RoutingProfileConfig {
            deny_tools: Some(vec!["read".to_string()]),
            ..RoutingProfileConfig::default()
        },
    )]);
    meta.with_profile_registry(ProfileRegistry::from_config(&profiles, "restricted"))
}

/// P1: the routing profile leaves the tool out (`dispatch_guards.rs:204`, in
/// `admit_target`). P2 (`visibility.rs:118`) is the same profile at the
/// invoke-scope check; the site mutants tell which of the two this call
/// reaches first.
#[tokio::test]
async fn p1_meta_routing_profile_at_admission() {
    let dir = tempfile::tempdir().expect("a log directory");
    let (meta, sent) = table_meta(&dir, BackendConfig::default());
    let meta = without_read(meta);
    let (error, decision) = refused(&meta, &dir, "alpha").await;
    assert_eq!(sent.load(Ordering::SeqCst), 0, "the backend was sent the call: {error}");
    assert_row(&decision, &refusal("p1_meta_routing_profile_at_admission", "routing_profile"));
}

/// N1: an unscoped caller names a server that matches nothing (`gate.rs:539`,
/// `denial.rs:21` or `policy.rs:414`; the site mutants tell which it reaches).
#[tokio::test]
async fn n1_meta_not_found() {
    let dir = tempfile::tempdir().expect("a log directory");
    let (meta, sent) = table_meta(&dir, BackendConfig::default());
    let (error, decision) = refused(&meta, &dir, "nowhere").await;
    assert_eq!(sent.load(Ordering::SeqCst), 0, "a backend was sent the call: {error}");
    let row = DecisionRow {
        rule_id: RuleId::Absent("the target matches nothing"),
        ..refusal("n1_meta_not_found", "not_found")
    };
    assert_row(&decision, &row);
}
