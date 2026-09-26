// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F9-T5, the gate half: a destructive call on the empty id is a sessionless
//! call, and each era's existing policy decides it. F9 changes no policy.

use super::*;
use crate::gateway::destructive_confirmation::ConfirmationPolicy;

fn gate_ctx(
    proxy: &crate::gateway::ProxyManager,
    policy: ConfirmationPolicy,
) -> crate::gateway::meta_mcp::MetaMcpCallerContext<'_> {
    crate::gateway::meta_mcp::MetaMcpCallerContext {
        confirmation: ConfirmationChannel::Elicit { proxy, policy },
        ..allow_all_ctx()
    }
}

async fn judge_on_the_empty_id(policy: ConfirmationPolicy) -> super::super::GateOutcome {
    let mux = Arc::new(crate::gateway::NotificationMultiplexer::new(
        Arc::new(BackendRegistry::new()),
        crate::config::StreamingConfig::default(),
    ));
    // A live session named "" exists; before F9 the prompt went to it.
    let _held = mux.seed_session("");
    let proxy = crate::gateway::ProxyManager::new(mux);
    let ctx = gate_ctx(&proxy, policy);
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        super::super::destructive_confirmation_gate(
            &RequestId::Number(1),
            "gateway_kill_server",
            &json!({"server": "brave"}),
            Some(""),
            &ctx,
        ),
    )
    .await
    .expect("nobody holds \"\", so the gate does not wait for an answer")
}

#[tokio::test]
async fn a_legacy_call_on_the_empty_id_proceeds_with_the_legacy_warning() {
    assert!(matches!(
        judge_on_the_empty_id(ConfirmationPolicy::for_legacy()).await,
        super::super::GateOutcome::Proceed
    ));
}

#[tokio::test]
async fn a_modern_call_on_the_empty_id_is_refused() {
    assert!(matches!(
        judge_on_the_empty_id(ConfirmationPolicy::for_modern()).await,
        super::super::GateOutcome::Refuse(_)
    ));
}
