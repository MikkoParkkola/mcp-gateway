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
    logged_meta_with(dir, Arc::new(Scripted(Ok(ok_result()))))
}

/// [`logged_meta`], `alpha` on `transport`.
fn logged_meta_with(
    dir: &tempfile::TempDir,
    transport: Arc<dyn crate::transport::Transport>,
) -> MetaMcp {
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(transport);
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

/// A target whose dispatch noted its own check: the route stage's note for
/// it is still taken, so the next target never inherits it.
#[tokio::test]
async fn a_route_note_is_taken_even_when_the_dispatch_noted_a_check() {
    use crate::gateway::meta_mcp::invoke::audit::{
        note_refused_by, take_refusal_kind, with_dispatch_scope, with_route_scope,
    };
    use crate::security::decision_record::DecisionKind;
    let (this, next) = with_route_scope(async {
        note_refused_by(DecisionKind::ToolPolicy, None);
        let (this, _) = with_dispatch_scope(async {
            note_refused_by(DecisionKind::Firewall, None);
            take_refusal_kind()
        })
        .await;
        (this, take_refusal_kind())
    })
    .await;
    assert_eq!(
        this,
        Some(DecisionKind::Firewall),
        "the dispatch's own check"
    );
    assert_eq!(next, None, "the next target starts from nothing");
}

/// A backend whose `tools/call` is refused at the send with the lender's
/// `Forbidden` (a lent credential that failed its recheck): nothing reached
/// the wire.
struct RefusedAtSend;

#[async_trait::async_trait]
impl crate::transport::Transport for RefusedAtSend {
    async fn request(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method == "tools/call" {
            return Err(crate::Error::Forbidden {
                code: -32001,
                status: 403,
                message: "per-user send refused: this credential was refused".to_string(),
            });
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

/// A refusal raised at the send on the meta route (`gateway_invoke`): the
/// route answers it as an error result, not a refusal, but the gateway's
/// lender refused the call, so its record must never read `default_allow`.
/// The check is about the caller's own credential, which no decision kind
/// names yet: kind `unrecorded`. Flips to that kind when an identity-standing
/// kind is added.
#[tokio::test]
async fn a_send_refusal_on_the_meta_route_records_unrecorded() {
    let dir = tempfile::tempdir().unwrap();
    let meta = logged_meta_with(&dir, Arc::new(RefusedAtSend));
    let who = api_key_caller();
    let caller = context(&AllowAll, &who);
    let args = json!({"server": "alpha", "tool": "read", "arguments": {}});
    let answer = meta
        .invoke_tool(&args, None, &caller)
        .await
        .expect("the meta route answers the refusal as an error result");
    assert!(answer.to_string().contains("per-user send refused"), "{answer}");
    let mut all = records(&dir);
    assert_eq!(all.len(), 1, "{all:?}");
    let record = all.remove(0);
    assert_eq!(record["decision"]["kind"], json!("unrecorded"), "{record}");
}
