// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7544 — the isolation guard and the metadata fill must agree.
//!
//! Own file because `catalogue_per_caller_tests.rs` would cross the 800-line
//! ceiling, and declared from it with `#[path]` so the module is compiled: an
//! undeclared `*_tests.rs` is invisible to `cargo test`, to coverage and to
//! grep. The fixtures it needs — `PerIdentityCatalogue`, `PerIdentityMint`,
//! `listed_for`, `identity` — are its parent's, reached through `super`.

use super::super::MetaMcp;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// The `stateless` propagating backend the cell below lists.
const PLAIN_STATELESS_BACKEND: &str = "plain_stateless_ledger";
const PLAIN_STATELESS_TOOL: &str = "plain_stateless_entry";

/// `session_mode = stateless` propagation; the cell below sets `required`.
fn stateless_propagation() -> IdentityPropagationConfig {
    IdentityPropagationConfig {
        strategy: PropagationStrategyKind::SignedAssertion,
        audience: "ledger".to_string(),
        required: false,
        session_mode: SessionMode::Stateless,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    }
}

/// A registered backend with a COLD tool cache, wired to `wire`.
///
/// Cold on purpose, and the opposite of `warm_backend`'s reason: a warm cache
/// is served without any upstream round trip, so an admitted backend would
/// record no fetch either and "no fetch occurred" would hold for both verdicts.
fn cold_backend_on(
    name: &str,
    config: BackendConfig,
    wire: &Arc<super::PerIdentityCatalogue>,
) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        name,
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::clone(wire) as Arc<dyn crate::transport::Transport>);
    backend
}

/// A wire that answers every credential with `tool`.
///
/// No per-identity arm: these cases must read the same whether the fill
/// forwards the caller's minted headers or drops them, so the guard's verdict
/// is the only thing they can be measuring.
fn one_answer_wire(tool: &str) -> Arc<super::PerIdentityCatalogue> {
    Arc::new(super::PerIdentityCatalogue {
        shared: tool.to_string(),
        per_identity: HashMap::new(),
        seen: parking_lot::Mutex::new(Vec::new()),
    })
}

/// `session_mode = stateless` with propagation REQUIRED — the production shape
/// the isolation guard actually refuses, and the one that loads.
///
/// NOT AN OAUTH BACKEND. The obvious fixture for a guard/fill agreement cell is
/// `oauth.enabled = true` beside `identity_propagation`, and `Config::validate`
/// REFUSES that pairing at load (`src/config/mod.rs:1005-1013`, the F3
/// refusal), as does `create_oauth_client`. A cell built on it pins a
/// configuration no deployment can hold. `required: true` reaches the same
/// guard through its third arm and is loadable.
fn required_stateless() -> IdentityPropagationConfig {
    IdentityPropagationConfig {
        required: true,
        ..stateless_propagation()
    }
}

/// GIVEN a multi-user gateway holding a `stateless` backend whose propagation
/// is REQUIRED
/// WHEN an identified caller and an unidentified one each list tools
/// THEN the identified caller is admitted AND answered from a fill that ran on
/// its own slot, while the unidentified caller is refused and nothing is
/// fetched for it.
///
/// T-S4 — INV-STATELESS-1, EXECUTABLE. The guard and the fill must agree:
/// `meta_route_isolation_refused_for_caller` admits **iff** `pool_key_for`
/// returns `PoolKey::PerUser` for the binding resolved in the same
/// `catalogue_credential_for` call. Both sides already read one
/// `resolve_propagation_credential` result; the remaining gap was the
/// `pool_key_for` arm, and closing it closes the disagreement by construction
/// rather than by a second guard.
///
/// THE TRANSCRIPT IS THE ASSERTION AND IT IS FIRST. "Admitted" and "answered
/// from the caller's own credential" are different facts, and a names assertion
/// placed ahead of the transcript would fail first and hide which one broke.
/// The cache is cold, so an admitted backend really does go upstream.
///
/// THE UNIDENTIFIED CALLER IS ITS OWN ROW, not a re-reading of the identified
/// one. A `required` backend with no resolved credential has no best-effort
/// downgrade that would still be that person (ADR-007 IDP.2/IDP.3), so it stays
/// refused — and that row is what keeps row 1 from being satisfiable by
/// loosening the guard for everybody.
#[tokio::test]
async fn a_required_stateless_backend_is_admitted_and_fetched_on_the_callers_slot() {
    let wire = one_answer_wire(PLAIN_STATELESS_TOOL);
    let registry = Arc::new(BackendRegistry::new());
    let backend = cold_backend_on(
        PLAIN_STATELESS_BACKEND,
        BackendConfig {
            identity_propagation: Some(required_stateless()),
            ..Default::default()
        },
        &wire,
    );
    backend.set_pooled_transport_for_test(
        &crate::backend::PoolKey::PerUser {
            binding: "alpha@ledger".to_string(),
        },
        Arc::clone(&wire) as Arc<dyn crate::transport::Transport>,
    );
    assert!(registry.register(backend), "fixture registration");

    let mut configs: HashMap<String, RoutingProfileConfig> = HashMap::new();
    configs.insert(
        "open".to_string(),
        RoutingProfileConfig {
            description: "denies nothing, so authorization cannot decide this case".to_string(),
            ..Default::default()
        },
    );
    let mut meta = MetaMcp::new(registry)
        .with_profile_registry(ProfileRegistry::from_config(&configs, "open"));
    // A `required` backend fails closed without a transparency logger — a mint
    // must never reach a caller without a durable audit record — so omitting it
    // would make every row below pass for that reason rather than the one under
    // test. The premise check beneath is what turns that into a failure here.
    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let path = file.path().to_string_lossy().to_string();
    std::mem::forget(file);
    meta.enable_transparency_log(Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::TransparencyLogConfig {
                enabled: true,
                path,
                key_id: "catalogue-stateless".to_string(),
                shared_secret: String::new(),
            },
        ))
        .expect("transparency logger opens"),
    ));
    meta.set_identity_propagation(Arc::new(super::PerIdentityMint));
    meta.set_multi_user(true);

    let alpha_id = super::identity("alpha");

    // PREMISE, checked rather than assumed. The mint MUST succeed, or the guard
    // refuses for a reason that has nothing to do with the pool slot.
    let (headers, binding) = meta
        .caller_credential_for_identity(PLAIN_STATELESS_BACKEND, Some(&alpha_id))
        .await;
    assert!(
        !headers.is_empty() && binding.is_some(),
        "premise: the caller must resolve a minted credential: \
         headers={headers:?} binding={binding:?}"
    );

    let alpha = super::listed_for(&meta, &super::super::identified_caller(&alpha_id)).await;

    // THE DISCRIMINATOR, FIRST. Admitted, and the fill that answered ran on
    // ALPHA'S OWN slot rather than the one every caller reads.
    assert_eq!(
        wire.seen.lock().clone(),
        vec![Some("alpha@ledger".to_string())],
        "a `required` `stateless` backend either refused an identified caller \
         or answered it from a fetch that did not carry its identity — the \
         guard and the fill disagree about who the caller is"
    );
    assert!(
        alpha.contains(&PLAIN_STATELESS_TOOL.to_string()),
        "the admitted caller was served nothing, so the transcript above \
         measures a fetch nobody received: {alpha:?}"
    );

    // ROW 2 — its own unidentified caller. A `required` backend stays refused
    // for a caller that resolves no credential, and nothing is fetched for it.
    let anonymous = super::listed_for(&meta, &super::super::anonymous_caller()).await;
    assert_eq!(
        wire.seen.lock().clone(),
        vec![Some("alpha@ledger".to_string())],
        "a `required` `stateless` backend was fetched for a caller that \
         resolved no credential, so the widened arm loosened the guard for \
         everybody rather than for the caller it can identify"
    );
    assert!(
        !anonymous.contains(&PLAIN_STATELESS_TOOL.to_string()),
        "a `required` backend was served to a caller carrying no end-user \
         identity: {anonymous:?}"
    );
}
