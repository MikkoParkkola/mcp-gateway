// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8914.API2A.13: a refusal answered with a code no outcome reads as a
//! refusal (-32603 for a response gate, -32003 for a spend budget) still names
//! its check, never `default_allow`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::{Scripted, api_key_caller, context, ok_result, records};
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::security::transparency_log::TransparencyLogConfig;

/// A gateway whose one backend `alpha` answers every call, logging to `dir`.
fn logged_meta(dir: &tempfile::TempDir) -> MetaMcp {
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Scripted(Ok(ok_result()))));
    let _ = registry.register(backend);
    let logger = crate::security::TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: dir
            .path()
            .join("audit.jsonl")
            .to_string_lossy()
            .into_owned(),
        key_id: "d1".to_string(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log");
    let mut meta = MetaMcp::new(registry);
    meta.enable_transparency_log(Arc::new(logger));
    meta
}

/// One refused call of `alpha`'s `read` on `meta`, and its one record.
async fn refused_record(meta: &MetaMcp, dir: &tempfile::TempDir) -> (crate::Error, Value) {
    let who = api_key_caller();
    let caller = context(&AllowAll, &who);
    let args = json!({"server": "alpha", "tool": "read", "arguments": {}});
    let error = meta
        .invoke_tool(&args, None, &caller)
        .await
        .expect_err("premise: the call is refused");
    let mut all = records(dir);
    assert_eq!(all.len(), 1, "{all:?}");
    (error, all.remove(0))
}

/// A response gate's block names `response_gate`.
#[tokio::test]
async fn a_response_gate_block_records_response_gate() {
    let dir = tempfile::tempdir().unwrap();
    let mut meta = logged_meta(&dir);
    // No contract declared for `read`, fail closed, enforced.
    meta.set_response_contract(crate::config::ResponseContractConfig {
        fail_closed: true,
        action_mode: true,
        ..crate::config::ResponseContractConfig::default()
    });
    let (error, record) = refused_record(&meta, &dir).await;
    assert!(error.to_string().contains("contract gate"), "{error}");
    assert_eq!(
        record["decision"]["kind"],
        json!("response_gate"),
        "{record}"
    );
}

/// A spend budget's refusal names `cost_budget`.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_budget_refusal_records_cost_budget() {
    use crate::cost_accounting::config::CostGovernanceConfig;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    // One call costs more than the tool's whole day.
    cfg.tool_costs.insert("read".to_string(), 1.0);
    cfg.budgets.per_tool.insert("read".to_string(), 0.5);
    let registry = Arc::new(crate::cost_accounting::registry::CostRegistry::new(&cfg));
    let enforcer = Arc::new(crate::cost_accounting::enforcer::BudgetEnforcer::new(
        cfg,
        Arc::clone(&registry),
    ));
    let meta = logged_meta(&dir).with_cost_governance(enforcer, registry);
    let (error, record) = refused_record(&meta, &dir).await;
    assert!(error.to_string().contains("budget exceeded"), "{error}");
    assert_eq!(record["decision"]["kind"], json!("cost_budget"), "{record}");
}

/// Two targets of one request, refused by different checks at the route
/// stage: each is answered with its own check, never the first target's.
#[tokio::test]
async fn a_route_stage_refusal_kind_is_taken_per_target() {
    use crate::gateway::meta_mcp::invoke::audit::{
        note_refused_by, take_refusal_kind, with_route_scope,
    };
    use crate::security::decision_record::DecisionKind;
    let (first, second) = with_route_scope(async {
        note_refused_by(DecisionKind::ToolPolicy, None);
        let first = take_refusal_kind();
        note_refused_by(DecisionKind::BackendScope, None);
        (first, take_refusal_kind())
    })
    .await;
    assert_eq!(first, Some(DecisionKind::ToolPolicy));
    assert_eq!(second, Some(DecisionKind::BackendScope));
}

/// A gateway started with no config file has no reload context; its records
/// still name the revision of the live config startup built.
#[test]
fn records_read_the_startup_live_config_without_a_reload_context() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    assert!(
        meta.live_config().is_none(),
        "nothing before startup sets it"
    );
    let live = Arc::new(crate::config_reload::LiveConfig::new(
        crate::config::Config::default(),
    ));
    meta.set_live_config(Arc::clone(&live));
    let served = meta.live_config().expect("startup's live config");
    assert!(Arc::ptr_eq(&served, &live));
}
