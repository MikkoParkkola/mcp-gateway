// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Bridged rounds the gateway refuses before they are sent: an undeclared
//! argument key, relay detection and the request firewall. Each ends the
//! exchange with the gateway's refusal, so the delivery records refused
//! while the cell is vouched, and nothing inside a composite.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::{Value, json};

use super::super::{BridgeDispatcher, MetaMcp};
use super::Slot;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::input_bridge::{BackendInvoker, BridgeError};
use crate::gateway::meta_mcp::InvokeScope;
use crate::gateway::router::CallerStanding;
use crate::identity_propagation::CallerProof;

/// Site 3: a bridged round whose arguments carry a key the tool does not
/// declare is refused before it is sent; the delivery records refused, and
/// inside a composite (the cell already unvouched) the same refusal marks
/// nothing.
#[tokio::test]
async fn an_undeclared_key_bridged_round_records_refused_only_while_vouched() {
    async fn effect(composite: bool) -> serde_json::Map<String, Value> {
        crate::gateway::delivery_facts::scope(async move {
            if composite {
                crate::gateway::delivery_facts::unvouched();
            }
            let backend = Arc::new(Backend::new(
                "edits",
                BackendConfig::default(),
                &FailsafeConfig::default(),
                Duration::from_secs(60),
            ));
            let slot = Arc::new(Slot::default());
            backend
                .set_transport_for_test(Arc::clone(&slot) as Arc<dyn crate::transport::Transport>);
            let registry = Arc::new(BackendRegistry::new());
            assert!(registry.register(backend));
            let meta = MetaMcp::new(registry);
            let arguments = json!({"edits": [], "zzextra": 1});
            let round = BridgeDispatcher {
                meta: &meta,
                caller: &crate::gateway::meta_mcp::authz_tests::ctx(
                    &crate::gateway::authz::AllowAll,
                ),
                server: "edits",
                tool: "edit",
                arguments: &arguments,
                prompt_cache_key: None,
                inbound_meta: None,
                want_full: false,
                session_id: None,
                arm_key: None,
                caller_identity: None,
                caller_proof: CallerProof::Anonymous,
                credential_owner: None,
                headers: &crate::transport::LentCredential::default(),
                cache_binding: None,
                account_credential: super::super::propagation::DispatchAccount::default(),
                api_key_name: None,
                trace_id: "site-3-bridged",
                policy_epoch: 0,
                protocol_revision: None,
                routing_profile: "default",
                scope: InvokeScope::allow_all(CallerStanding::Standard),
                captured: meta.backends.for_test().get("edits"),
                managed: None,
                account_refusal: &parking_lot::Mutex::new(None),
                reservation: &parking_lot::Mutex::new(None),
                relay: super::super::relay::RelayKey::unkeyed_for_test("site-3"),
                relay_refused: &parking_lot::Mutex::new(None),
            };
            let outcome = round.invoke(json!({})).await;
            assert_eq!(slot.calls.load(Ordering::SeqCst), 0, "premise: never sent");
            assert!(
                matches!(outcome, Err(BridgeError::NotAdmitted { .. })),
                "premise: the key refusal: {outcome:?}"
            );
            let mut fields = serde_json::Map::new();
            crate::gateway::delivery_facts::record_fields(
                crate::gateway::delivery_facts::snapshot().as_ref(),
                false,
                &mut fields,
            );
            fields
        })
        .await
    }
    let lone = effect(false).await;
    assert_eq!(lone["response_effect"], "refused", "{lone:?}");
    let composite = effect(true).await;
    assert!(composite.get("response_effect").is_none(), "{composite:?}");
}

/// What refuses the bridged round in [`a_firewall_refused_bridged_round_records_refused_only_while_vouched`].
#[cfg(feature = "firewall")]
#[derive(Clone, Copy, Debug)]
enum RoundBlock {
    /// Relay detection under `block`, on an unkeyed caller (site 2).
    Relay,
    /// The request firewall, on the round's answers (the chokepoint).
    Request,
}

/// Sites 2 and the bridged chokepoint: a bridged round the firewall refuses
/// before it is sent ends the exchange with that refusal; the delivery
/// records refused, and inside a composite (the cell already unvouched) the
/// same refusal marks nothing.
// One BridgeDispatcher literal per cell, as every bridged row here builds
// it: splitting it would hide which field the row varies.
#[allow(clippy::too_many_lines)]
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_firewall_refused_bridged_round_records_refused_only_while_vouched() {
    use crate::security::firewall::{CollusionAction, CollusionConfig, Firewall, FirewallConfig};
    async fn effect(block: RoundBlock, composite: bool) -> serde_json::Map<String, Value> {
        crate::gateway::delivery_facts::scope(async move {
            if composite {
                crate::gateway::delivery_facts::unvouched();
            }
            let backend = Arc::new(Backend::new(
                "edits",
                BackendConfig::default(),
                &FailsafeConfig::default(),
                Duration::from_secs(60),
            ));
            let registry = Arc::new(BackendRegistry::new());
            assert!(registry.register(Arc::clone(&backend)));
            let mut meta = MetaMcp::new(registry);
            let config = match block {
                RoundBlock::Relay => FirewallConfig {
                    collusion: CollusionConfig {
                        action: CollusionAction::Block,
                        sources: vec!["edits:*".to_string()],
                        ..CollusionConfig::default()
                    },
                    ..FirewallConfig::default()
                },
                RoundBlock::Request => FirewallConfig {
                    enabled: true,
                    scan_requests: true,
                    ..FirewallConfig::default()
                },
            };
            meta.set_firewall(Some(Arc::new(
                Firewall::from_config(config, None).with_continuations(meta.continuation()),
            )));
            let slot = Arc::new(Slot::default());
            backend
                .set_transport_for_test(Arc::clone(&slot) as Arc<dyn crate::transport::Transport>);
            let arguments = json!({"edits": []});
            let relay_refused = parking_lot::Mutex::new(None);
            let round = BridgeDispatcher {
                meta: &meta,
                caller: &crate::gateway::meta_mcp::authz_tests::ctx(
                    &crate::gateway::authz::AllowAll,
                ),
                server: "edits",
                tool: "edit",
                arguments: &arguments,
                prompt_cache_key: None,
                inbound_meta: None,
                want_full: false,
                session_id: None,
                arm_key: None,
                caller_identity: None,
                caller_proof: CallerProof::Anonymous,
                credential_owner: None,
                headers: &crate::transport::LentCredential::default(),
                cache_binding: None,
                account_credential: super::super::propagation::DispatchAccount::default(),
                api_key_name: None,
                trace_id: "site-2-bridged",
                policy_epoch: 0,
                protocol_revision: None,
                routing_profile: "default",
                scope: InvokeScope::allow_all(CallerStanding::Standard),
                captured: meta.backends.for_test().get("edits"),
                managed: None,
                account_refusal: &parking_lot::Mutex::new(None),
                reservation: &parking_lot::Mutex::new(None),
                relay: super::super::relay::RelayKey::unkeyed_for_test("site-2"),
                relay_refused: &relay_refused,
            };
            // The shell-injection premise of the bridged firewall row above.
            let account = ["; rm -", "rf / "].concat();
            let answers = json!({"k1": {"action": "accept", "content": {"account": account}}});
            let outcome = round.invoke(json!({"inputResponses": answers})).await;
            assert!(
                matches!(outcome, Err(BridgeError::NotAdmitted { .. })),
                "{block:?} premise: refused: {outcome:?}"
            );
            assert!(
                relay_refused.lock().is_some(),
                "{block:?} premise: the refusal waits for the call site"
            );
            assert_eq!(
                slot.calls.load(Ordering::SeqCst),
                0,
                "{block:?} premise: never sent"
            );
            let mut fields = serde_json::Map::new();
            crate::gateway::delivery_facts::record_fields(
                crate::gateway::delivery_facts::snapshot().as_ref(),
                false,
                &mut fields,
            );
            fields
        })
        .await
    }
    for block in [RoundBlock::Relay, RoundBlock::Request] {
        let lone = effect(block, false).await;
        assert_eq!(lone["response_effect"], "refused", "{block:?} {lone:?}");
        let composite = effect(block, true).await;
        assert!(
            composite.get("response_effect").is_none(),
            "{block:?} {composite:?}"
        );
    }
}
