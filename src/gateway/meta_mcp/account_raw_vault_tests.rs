// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Dispatch half of the raw-`vault` fallback: the RESOLVER must refuse, not the
//! config loader.
//!
//! DELIBERATE DEFENSIVE SEAM, STATED PLAINLY. `fixture_config(..)` is used ONLY
//! to obtain a raw `BackendConfig`; `compile` is NOT called here. Once the
//! config-side fix lands, this configuration cannot be loaded at all — so a
//! test that went through `compile` would be refused before dispatch and would
//! prove nothing about `resolve_caller_credential`. Registering the raw backend
//! directly is exactly the state a hot reload rebuilt from raw config leaves
//! behind, and it is the only way to drive the resolver's own decision.
//!
//! WHAT THE RESOLVER SEES: `account_descriptor_id()` is `None` (no `account`
//! key), so the descriptorless branch borrows `self.identity_propagation` — the
//! unrelated process-wide `SignedAssertionStrategy` — and mints a gateway
//! assertion for a backend that asked for VAULT custody. Note the refusal
//! cannot be routed through the existing `refuse` closure: on `required: false`
//! that closure returns the empty credential and the call falls through to the
//! backend's static header. Both flags must end in `Err` with ZERO backend calls.
//!
//! NO custody, NO grant, NO per-backend strategy installed, NO direct mint: the
//! real `code_mode_execute` -> `invoke_tool` -> `resolve_caller_credential`
//! entry decides. Session mode is `Stateless` and the audience is identical for
//! control and negatives, so a missing per-user pool slot can never be confused
//! with a refusal.

use super::*;

const RAW_BACKEND: &str = "vaultless-backend";
const RAW_AUDIENCE: &str = "https://vaultless.example.invalid/";

fn raw_cfg(strategy: PropagationStrategyKind, required: bool) -> IdentityPropagationConfig {
    IdentityPropagationConfig {
        strategy,
        audience: RAW_AUDIENCE.to_string(),
        required,
        session_mode: crate::identity_propagation::SessionMode::Stateless,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    }
}

/// The SAME assembly for control and negatives: one raw registered backend, one
/// shared stateless capturing transport, one durable transparency log, one
/// process-wide signed-assertion strategy. `compile` is deliberately not called.
fn raw_gateway(idp: IdentityPropagationConfig) -> (MetaMcp, Arc<Dispatches>) {
    let config = fixture_config(&[(RAW_BACKEND, Bind::Propagation(idp))], &[]);
    let declared = config.backends[RAW_BACKEND].clone();

    let registry = Arc::new(BackendRegistry::new());
    let dispatches = Arc::new(Dispatches::default());
    let backend = Arc::new(Backend::new(
        RAW_BACKEND,
        declared,
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(CapturingTransport {
        dispatches: Arc::clone(&dispatches),
    }) as Arc<dyn crate::transport::Transport>);
    assert!(registry.register(backend), "fixture registry must accept");

    let mut meta = MetaMcp::new(registry);
    meta.enable_transparency_log(leaked_transparency_logger());
    let gateway_key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    meta.set_identity_propagation(Arc::new(
        crate::identity_propagation::SignedAssertionStrategy::new(gateway_key, ASSERTION_TTL_SECS),
    ));
    (meta, dispatches)
}

/// CONTRACT: a registered backend asking for `vault` with no account reference
/// has no custody to answer for anyone, so dispatch is refused — the unrelated
/// global signed-assertion strategy is not a substitute, and `required: false`
/// is not permission to fall through to the static header.
///
/// CURRENT CODE: `account_bound == false`, the global strategy is borrowed, and
/// a gateway assertion goes on the wire. Semantic RED.
#[tokio::test]
async fn raw_vault_backend_must_not_borrow_the_global_signed_assertion_strategy() {
    let alice = identity("alice-subject");

    // POSITIVE CONTROL FIRST, same assembly, same audience, same session mode:
    // a matched `signed_assertion` backend REACHES the transport and carries a
    // minted assertion — not the backend's static header.
    let (meta, dispatches) = raw_gateway(raw_cfg(PropagationStrategyKind::SignedAssertion, true));
    execute(&meta, RAW_BACKEND, Some(&alice))
        .await
        .expect("a matched signed_assertion backend must still dispatch");
    let call = dispatches.only();
    assert!(
        !call.headers.is_empty(),
        "the control must carry a minted per-request credential: {call:?}"
    );
    assert!(
        call.headers.iter().all(|(_, v)| v != STATIC_FALLBACK),
        "the control must carry the ASSERTION, not the backend's static header: {call:?}"
    );

    for required in [true, false] {
        let (meta, dispatches) = raw_gateway(raw_cfg(PropagationStrategyKind::Vault, required));
        let error = execute(&meta, RAW_BACKEND, Some(&alice))
            .await
            .err()
            .unwrap_or_else(|| {
                panic!("a raw vault backend (required: {required}) must be refused at dispatch")
            })
            .to_string();
        assert!(
            error.to_lowercase().contains("vault"),
            "the refusal must name the strategy that has no custody (required: {required}): \
             {error}"
        );
        assert_eq!(
            dispatches.count(),
            0,
            "a refused vault backend must make NO backend call — not one with a borrowed \
             assertion and not one with the static header (required: {required}): {:?}",
            dispatches.calls()
        );
    }
}
