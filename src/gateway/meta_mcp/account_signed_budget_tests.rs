// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8353 slice 3a (NONCEFX.9), K-spend-refresh: a signed `gateway_invoke`
//! whose account credential was refreshed before the spend budget refused it
//! keeps its nonce spent. The refresh rotated a real grant (an effect), so it
//! dropped the refund witness.

use std::time::Duration;

use serde_json::{Value, json};

use super::{
    ALICE_WORK_TOKEN, Bind, Descriptors, WORK, account_key, caller_as, custody_with, gateway,
    grant, identity, slots,
};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::refund_witness::RefundWitness;
use crate::gateway::meta_mcp::signing::{NONCE_META, SigningInvocationContext, SigningScope};
use crate::security::message_signing::MessageSigner;

const NONCE: &str = "refresh-budget-nonce";

/// A hardened `tools/call` captured as the adapters capture it.
fn captured(name: &str, arguments: &Value) -> (SigningInvocationContext, Value) {
    let mut request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": name, "arguments": arguments, "_meta": {(NONCE_META): NONCE}}});
    let context =
        SigningInvocationContext::capture_scoped(&mut request, SigningScope::EveryToolCall);
    let arguments = request["params"]["arguments"].clone();
    (context, arguments)
}

/// Whether `NONCE` is still free: an ordinary call presenting it is admitted.
fn nonce_is_free(meta: &MetaMcp) -> bool {
    let (mut later, arguments) = captured("gateway_list_servers", &json!({}));
    meta.prepare_signing_for_call(
        &mut later,
        "gateway_list_servers",
        &arguments,
        None,
        &caller_as(None, None),
    )
    .is_ok()
        && !later.awaits_admission()
}

/// Spend governance with `read` at 1.0 and `k-budget` allowed 0.5, so the
/// first call is refused.
fn budget(meta: MetaMcp) -> MetaMcp {
    use crate::cost_accounting::config::CostGovernanceConfig;
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.tool_costs.insert("read".to_string(), 1.0);
    cfg.budgets.per_key.insert("k-budget".to_string(), 0.5);
    let registry = std::sync::Arc::new(crate::cost_accounting::registry::CostRegistry::new(&cfg));
    let enforcer = std::sync::Arc::new(crate::cost_accounting::enforcer::BudgetEnforcer::new(
        cfg,
        std::sync::Arc::clone(&registry),
    ));
    meta.with_cost_governance(enforcer, registry)
}

/// Alice's slot on `mail` before the call (MIK-8356): a per-user call judges
/// the caller's own catalogue first, so a cold slot is filled.
#[derive(Clone, Copy)]
enum Slot {
    /// Seeded under the seeded and the refreshed grant's binding: the refresh
    /// is the call's only effect.
    Warm,
    /// Unfilled: the catalogue fill is a second effect.
    Cold,
}

/// What a refused call left behind.
struct Refused {
    wire: Value,
    refreshes: usize,
    fills: u64,
    dispatched: bool,
    nonce_free: bool,
}

/// K-spend-refresh: alice's work grant is expired, so resolving the account
/// credential refreshes it; the spend budget then refuses the call. The
/// context holds the witness as admission leaves it.
async fn a_spend_refusal_after_a_refresh(slot: Slot) -> Refused {
    let custody = custody_with(&[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, 0))]);
    let installed = custody.installed();
    // The schema check off, so no argument-key fill adds an effect of its own
    // (mF-account survived run 38177519271 that way).
    super::gateway::SCHEMA_OFF.with(|off| off.set(true));
    let (_log, mut meta, dispatches) = gateway(
        &[("mail", Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &installed,
        &slots(&[("alice", WORK)]),
    );
    super::gateway::SCHEMA_OFF.with(|off| off.set(false));
    meta.enable_message_signing(
        MessageSigner::new(
            b"refresh-budget-key-0123456789abcdef".to_vec(),
            None,
            "k1".into(),
        ),
        Duration::from_secs(300),
        true,
    );
    let meta = budget(meta);

    let alice = identity("alice");
    let mut caller = caller_as(Some(&alice), None);
    caller.api_key_name = Some("k-budget");
    caller.authentication = crate::gateway::meta_mcp::Authentication::Authenticated;
    // An API key: only an API key is charged per key (MIK-8507).
    caller.credential_kind = crate::security::audit::CredentialKind::ApiKey;
    if matches!(slot, Slot::Warm) {
        let read: crate::protocol::Tool =
            serde_json::from_value(json!({"name": "read", "inputSchema": {"type": "object"}}))
                .expect("a tool");
        for revision in [super::SEEDED_REVISION, super::SEEDED_REVISION + 1] {
            meta.seed_caller_catalogue_for_test(
                "mail",
                MetaMcp::proof_of(&caller),
                &super::expected_identity_key("alice", WORK, revision),
                vec![read.clone()],
            );
        }
    }
    let call = json!({"server": "mail", "tool": "read", "arguments": {}});
    let (mut signing, arguments) = captured("gateway_invoke", &call);
    meta.prepare_signing_for_call(
        &mut signing,
        "gateway_invoke",
        &arguments,
        Some("s"),
        &caller,
    )
    .expect("the budget refusal is the dispatcher's to answer");
    assert!(
        !signing.awaits_admission(),
        "premise: the nonce was admitted"
    );
    // What admission does on both adapters (`admit_meta_sync`): the context
    // holds the witness, so only the call's own effects can cost the refund.
    signing.keep_witness(RefundWitness::at_capture());
    caller.signing = Some(&signing);
    let response = Box::pin(meta.handle_tools_call(
        crate::protocol::RequestId::Number(7),
        "gateway_invoke",
        arguments,
        Some("s"),
        caller,
    ))
    .await;
    let wire = serde_json::to_value(&response).expect("a response serializes");
    assert!(
        wire.to_string().to_lowercase().contains("budget exceeded"),
        "premise: the spend refusal: {wire}"
    );
    Refused {
        wire,
        refreshes: custody.refreshes(),
        fills: meta
            .backends
            .for_test()
            .get("mail")
            .expect("fixture backend")
            .list_fills(),
        dispatched: !dispatches.calls().is_empty(),
        nonce_free: nonce_is_free(&meta),
    }
}

/// Warm: the refresh is the only effect. Red on base: the refusal refunds the
/// nonce though the refresh took effect. On an account-bound MCP backend the
/// account credential reaches the call as its propagated credential
/// (`cache_binding` set), so this row pins the `minted` arm (mF-mint); the
/// capability route's twin, `account_rest_signed_budget_tests.rs`, pins the
/// `account` arm.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_spend_refusal_after_a_refresh_keeps_the_nonce() {
    let refused = a_spend_refusal_after_a_refresh(Slot::Warm).await;
    assert_eq!(refused.refreshes, 1, "the refused call refreshed the grant");
    assert_eq!(refused.fills, 0, "premise: the check filled nothing");
    assert!(!refused.dispatched, "nothing reached the backend");
    assert!(
        !refused.nonce_free,
        "the nonce was given back after a refresh: {}",
        refused.wire
    );
}

/// Cold (MIK-8356): the caller's own catalogue is filled before the refusal,
/// a second effect beside the refresh; the nonce stays spent. Pins the two
/// together: a broken fill carry alone stays green behind the refresh. The
/// fill's carry (`schema_effect`) is isolated by the non-minting cold-schema
/// row in `router/mcp_nonce_witness_tests.rs`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_spend_refusal_after_a_refresh_and_a_cold_fill_keeps_the_nonce() {
    let refused = a_spend_refusal_after_a_refresh(Slot::Cold).await;
    assert_eq!(refused.refreshes, 1, "the refused call refreshed the grant");
    assert_eq!(
        refused.fills, 1,
        "premise: the caller's own catalogue was filled"
    );
    assert!(!refused.dispatched, "nothing reached the backend");
    assert!(
        !refused.nonce_free,
        "the nonce was given back after a refresh and a fill: {}",
        refused.wire
    );
}
