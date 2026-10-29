// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8340 row 10 (ORACLE.4, test plan r2.1): when a caller's own catalogue
//! and the shared cache hold different schemas for one tool, a listing
//! follows the caller's view. Withheld by the caller's invalid schema, the
//! tool is listed exactly as where the caller's catalogue lacks it (RED on
//! base); valid in the caller's view and invalid in the shared one, it is
//! listed with the caller's schema (the control).

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::MetaMcp;
use super::catalogue_per_caller_tests::{identity, install_minting};
use super::identified_caller;
use crate::backend::{Backend, BackendRegistry, PoolKey};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::protocol::{JsonRpcResponse, RequestId};

const BACKEND: &str = "ledger_hub";
/// The slot `PerIdentityMint` binds subject `alpha` to on audience `ledger`.
const BINDING: &str = "alpha@ledger";
const TOOL: &str = "read";
const SIBLING: &str = "note";

fn tool(name: &str, schema: &Value) -> crate::protocol::Tool {
    serde_json::from_value(json!({
        "name": name, "description": "A ledger tool.", "inputSchema": schema
    }))
    .expect("a tool")
}

fn valid() -> Value {
    json!({"type": "object", "properties": {"q": {"type": "string"}}})
}

fn invalid() -> Value {
    json!({"type": "array"})
}

/// A transport answering `tools/list` with a fixed catalogue.
struct Listing(Value);

#[async_trait::async_trait]
impl crate::transport::Transport for Listing {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        Ok(JsonRpcResponse::success(
            RequestId::Number(1),
            json!({"tools": self.0}),
        ))
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

/// A multi-user gateway whose per-user backend holds `shared` in the shared
/// slot and `caller` (the tool with that schema, or no tool) in alpha's.
/// A gateway and its audit log. Fields drop in declaration order, so the log
/// goes after the `MetaMcp` that writes to it.
struct Gateway {
    meta: MetaMcp,
    _log: crate::security::transparency_log::temp::TempLog,
}

fn gateway(caller: Option<&Value>, shared: &Value) -> Gateway {
    let backend = Arc::new(Backend::new(
        BACKEND,
        BackendConfig {
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "ledger".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..Default::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let shared_tools = vec![tool(TOOL, shared), tool(SIBLING, &valid())];
    let mut caller_tools = vec![tool(SIBLING, &valid())];
    if let Some(schema) = caller {
        caller_tools.push(tool(TOOL, schema));
    }
    backend.set_transport_for_test(Arc::new(Listing(
        serde_json::to_value(&shared_tools).expect("tools"),
    )));
    backend.set_pooled_transport_for_test(
        &PoolKey::PerUser {
            binding: BINDING.to_string(),
        },
        Arc::new(Listing(serde_json::to_value(&caller_tools).expect("tools"))),
    );
    backend.store_shared_tools_for_test(shared_tools);
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(backend), "fixture registration");
    let log = crate::security::transparency_log::temp::TempLog::new();
    let mut meta = MetaMcp::new(registry);
    install_minting(&mut meta, &log);
    meta.set_multi_user(true);
    // alpha's catalogue, as alpha's own fill leaves it (stored and indexed).
    let alpha = identity("alpha");
    let proof = MetaMcp::proof_of(&identified_caller(&alpha));
    meta.seed_caller_catalogue_for_test(BACKEND, proof, BINDING, caller_tools);
    Gateway { meta, _log: log }
}

/// `gateway_list_tools` for `BACKEND` as alpha.
async fn listing(meta: &MetaMcp) -> Value {
    let alpha = identity("alpha");
    meta.list_tools(
        &json!({"server": BACKEND}),
        None,
        &identified_caller(&alpha),
    )
    .await
    .expect("gateway_list_tools answers")
}

/// The listed entry named `name`, if any.
fn entry<'a>(listed: &'a Value, name: &str) -> Option<&'a Value> {
    listed["tools"]
        .as_array()?
        .iter()
        .find(|t| t["name"] == name)
}

/// Row 10, caller invalid / shared valid: the caller's listing omits the tool
/// exactly as where its catalogue lacks it. RED on base.
#[tokio::test]
async fn row10_caller_invalid_schema_is_listed_as_absent() {
    let withheld = listing(&gateway(Some(&invalid()), &valid()).meta).await;
    let absent = listing(&gateway(None, &valid()).meta).await;
    assert!(
        entry(&absent, SIBLING).is_some(),
        "premise: the caller's sibling is not listed: {absent}"
    );
    assert!(
        entry(&withheld, TOOL).is_none(),
        "row 10: a tool the caller's schema withholds is listed: {withheld}"
    );
    assert_eq!(
        withheld, absent,
        "row 10: withheld {withheld} vs absent {absent}"
    );
}

/// Row 10, caller valid / shared invalid (control): the caller's listing
/// shows the tool, with the caller's schema where it shows one.
#[tokio::test]
async fn row10_caller_valid_schema_is_listed_from_the_callers_view() {
    let listed = listing(&gateway(Some(&valid()), &invalid()).meta).await;
    let shown = entry(&listed, TOOL)
        .unwrap_or_else(|| panic!("row 10 control: the caller's valid tool is hidden: {listed}"));
    if let Some(schema) = shown.get("inputSchema") {
        assert_eq!(
            schema,
            &valid(),
            "row 10 control: not the caller's schema bytes"
        );
    }
}

/// `gateway_list_disabled_capabilities` for alpha, once `TOOL`'s error
/// budget has disabled it on `meta`.
fn disabled_listing(meta: &MetaMcp) -> Value {
    let cfg = meta.capability_budget_config.read().clone();
    for _ in 0..=cfg.window_size.max(cfg.min_samples) {
        meta.kill_switch
            .record_capability_failure(BACKEND, TOOL, &cfg);
    }
    assert!(
        meta.kill_switch.is_capability_disabled(BACKEND, TOOL),
        "premise: the budget did not disable {TOOL}"
    );
    let alpha = identity("alpha");
    meta.list_disabled_capabilities(identified_caller(&alpha).scope(), None)
        .expect("the disabled list answers")
}

/// Row 10b (gpt and grok seats): a disabled tool withheld by its schema is
/// not named by the disabled-capability list, as its listing omits it; the
/// same disabled tool with a valid schema is named (the control).
#[tokio::test]
async fn row10b_the_disabled_list_omits_a_schema_withheld_tool() {
    let named = |listed: &Value| {
        listed["disabled_capabilities"]
            .as_array()
            .is_some_and(|all| all.iter().any(|e| e["capability"] == TOOL))
    };
    let control = disabled_listing(&gateway(Some(&valid()), &valid()).meta);
    assert!(
        named(&control),
        "premise: the valid disabled tool is not named: {control}"
    );
    let withheld = disabled_listing(&gateway(Some(&invalid()), &invalid()).meta);
    assert!(
        !named(&withheld),
        "row 10b: a schema-withheld tool is named: {withheld}"
    );
}

/// The text alpha gets for `gateway_invoke` of `reaf` on `BACKEND`, one edit
/// from `TOOL`: a miss, with a "did you mean?" hint when one is admitted.
async fn miss_text(meta: &MetaMcp) -> String {
    let alpha = identity("alpha");
    let args = json!({"server": BACKEND, "tool": "reaf", "arguments": {}});
    let response = Box::pin(meta.handle_tools_call(
        crate::protocol::RequestId::Number(1),
        "gateway_invoke",
        args,
        None,
        identified_caller(&alpha),
    ))
    .await;
    let body = serde_json::to_value(&response).expect("a response serialises");
    body.pointer("/result/content/0/text")
        .or_else(|| body.pointer("/error/message"))
        .and_then(Value::as_str)
        .map_or_else(|| body.to_string(), str::to_owned)
}

/// Row 10c (gpt seat): a miss's "did you mean?" hint judges a candidate by
/// the caller's own catalogue entry. Withheld by the caller's invalid
/// schema (valid in the shared cache), the tool is never suggested: the
/// text equals the one where the caller's catalogue lacks it. The control
/// (valid for the caller) is suggested.
#[tokio::test]
async fn row10c_a_miss_never_suggests_a_tool_the_callers_schema_withholds() {
    let control = miss_text(&gateway(Some(&valid()), &valid()).meta).await;
    assert!(
        control.contains(TOOL) && control.contains("reaf"),
        "premise: the miss does not suggest the caller's valid tool: {control}"
    );
    let withheld = miss_text(&gateway(Some(&invalid()), &valid()).meta).await;
    let absent = miss_text(&gateway(None, &valid()).meta).await;
    assert_eq!(
        withheld, absent,
        "row 10c: withheld {withheld} vs absent {absent}"
    );
}
