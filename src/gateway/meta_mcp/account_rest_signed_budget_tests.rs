// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8353 slice 3a (NONCEFX.9), K-spend-refresh on the capability route: a
//! signed `gateway_invoke` of a REST capability bound to an account, whose
//! expired grant is refreshed before the spend budget refuses the call, keeps
//! its nonce spent. On this route the account credential is the call's only
//! effect (no propagation mint; the schema check never fills a capability),
//! so mutant mF-account turns this row red.

use std::time::Duration;

use serde_json::{Value, json};

use super::super::account_resolver_fixture::{
    ALICE_WORK_TOKEN, WORK, account_key, custody_with, grant,
};
use super::{
    CAPABILITIES, TOOL, backend_with, caller, capability, identity, installed_gateway_built,
    managed,
};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::refund_witness::RefundWitness;
use crate::gateway::meta_mcp::signing::{NONCE_META, SigningInvocationContext, SigningScope};
use crate::security::message_signing::MessageSigner;

const NONCE: &str = "rest-refresh-budget-nonce";
const UNROUTABLE: &str = "https://rest-account-control.invalid";

/// A hardened `tools/call` captured as the adapters capture it.
fn captured(name: &str, arguments: &Value) -> (SigningInvocationContext, Value) {
    let mut request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": name, "arguments": arguments, "_meta": {(NONCE_META): NONCE}}});
    let context =
        SigningInvocationContext::capture_scoped(&mut request, SigningScope::EveryToolCall);
    let arguments = request["params"]["arguments"].clone();
    (context, arguments)
}

/// Signing on, and spend governance with `TOOL` at 1.0 and `k-budget`
/// allowed 0.5, so the first call is refused.
fn signed_and_budgeted(mut meta: MetaMcp) -> MetaMcp {
    use crate::cost_accounting::config::CostGovernanceConfig;
    meta.enable_message_signing(
        MessageSigner::new(
            b"rest-refresh-budget-key-0123456789ab".to_vec(),
            None,
            "k1".into(),
        ),
        Duration::from_secs(300),
        true,
    );
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.tool_costs.insert(TOOL.to_string(), 1.0);
    cfg.budgets.per_key.insert("k-budget".to_string(), 0.5);
    let registry = std::sync::Arc::new(crate::cost_accounting::registry::CostRegistry::new(&cfg));
    let enforcer = std::sync::Arc::new(crate::cost_accounting::enforcer::BudgetEnforcer::new(
        cfg,
        std::sync::Arc::clone(&registry),
    ));
    meta.with_cost_governance(enforcer, registry)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_spend_refusal_after_a_capability_account_refresh_keeps_the_nonce() {
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, 0))]);
    let installed = custody.installed();
    let (_log, meta, registry) =
        installed_gateway_built(&[(WORK, managed(WORK))], &installed, signed_and_budgeted);
    let backend = backend_with(
        &registry,
        capability(UNROUTABLE, "oauth:google", Some(WORK)),
    )
    .expect("the capability must register");
    meta.set_capabilities(std::sync::Arc::clone(&backend));

    let alice = identity("alice");
    let mut context = caller(Some(&alice));
    context.api_key_name = Some("k-budget");
    context.authentication = crate::gateway::meta_mcp::Authentication::Authenticated;
    // An API key: only an API key is charged per key (MIK-8507).
    context.credential_kind = crate::security::audit::CredentialKind::ApiKey;
    let call = json!({"server": CAPABILITIES, "tool": TOOL, "arguments": {}});
    let (mut signing, arguments) = captured("gateway_invoke", &call);
    meta.prepare_signing_for_call(
        &mut signing,
        "gateway_invoke",
        &arguments,
        Some("s"),
        &context,
    )
    .expect("the budget refusal is the dispatcher's to answer");
    assert!(
        !signing.awaits_admission(),
        "premise: the nonce was admitted"
    );
    // What admission leaves on the context on both adapters.
    signing.keep_witness(RefundWitness::at_capture());
    context.signing = Some(&signing);
    let response = Box::pin(meta.handle_tools_call(
        crate::protocol::RequestId::Number(7),
        "gateway_invoke",
        arguments,
        Some("s"),
        context,
    ))
    .await;
    let wire = serde_json::to_value(&response).expect("a response serializes");

    assert!(
        wire.to_string().to_lowercase().contains("budget exceeded"),
        "the spend refusal: {wire}"
    );
    assert_eq!(
        custody.refreshes(),
        1,
        "the refused call refreshed the grant"
    );

    let (mut later, arguments) = captured("gateway_list_servers", &json!({}));
    let free = meta
        .prepare_signing_for_call(
            &mut later,
            "gateway_list_servers",
            &arguments,
            None,
            &caller(None),
        )
        .is_ok()
        && !later.awaits_admission();
    assert!(!free, "the nonce was given back after a refresh: {wire}");
}
