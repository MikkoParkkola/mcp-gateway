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

/// The backend that is BOTH behind one gateway-held OAuth login and configured
/// `stateless` — the shape MIK-7544 names, and the shape no other fixture has.
const OAUTH_STATELESS_BACKEND: &str = "oauth_stateless_ledger";
/// The tool its gateway-held account would answer with, which nobody may see.
const GATEWAY_ACCOUNT_TOOL: &str = "gateway_account_private_ledger";
/// The same propagation with NO gateway-held OAuth login: still admitted.
const PLAIN_STATELESS_BACKEND: &str = "plain_stateless_ledger";
const PLAIN_STATELESS_TOOL: &str = "plain_stateless_entry";

/// `session_mode = stateless`, propagation configured and NOT required.
///
/// `required: false` is load-bearing. A `required` backend with no resolved
/// per-user credential is refused by `enforce_oauth_isolation_for`'s third arm
/// whatever the first arm decides, so the omission below would hold without the
/// OAuth arm ever being consulted and the case would prove nothing.
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

/// GIVEN a multi-user gateway holding a backend that is behind one
/// gateway-held OAuth login AND configured `session_mode = stateless`
/// WHEN an identified caller lists tools
/// THEN the backend is OMITTED, and no `tools/list` is sent for it at all.
///
/// A DIFFERENT LEAK CLASS FROM THE ONE ALREADY CLOSED (MIK-7544). The fill
/// fix stopped one caller's minted credential reaching the SHARED slot; this
/// is the mirror image. The guard admitted on credential POSSESSION, the fill
/// then dropped those headers because `pool_key_for` hands a `stateless`
/// backend `PoolKey::Shared`, and the fetch went upstream under the
/// GATEWAY-HELD account — whose private catalogue landed in the one entry every
/// caller reads. Gateway-account-to-every-caller, not caller-to-caller.
///
/// THE TRANSCRIPT IS THE ASSERTION, AND IT IS FIRST. "No fetch occurred" and
/// "a fetch returned nothing" are different facts and only the first proves the
/// guard fired; a names assertion placed ahead of it would fail first and hide
/// it. The cache is cold (`cold_backend_on`) so an admitted backend really
/// would go upstream — against a warm one the transcript is empty either way.
///
/// THE CONTROL IS THE SAME PROPAGATION WITHOUT THE OAUTH LOGIN. It must still
/// be admitted and still be fetched: the verdict now follows the pool slot, and
/// the slot is not a licence to omit every `stateless` backend.
#[tokio::test]
async fn an_isolated_oauth_stateless_backend_is_omitted_not_fetched_as_the_gateway() {
    let oauth_wire = one_answer_wire(GATEWAY_ACCOUNT_TOOL);
    let plain_wire = one_answer_wire(PLAIN_STATELESS_TOOL);
    let registry = Arc::new(BackendRegistry::new());
    assert!(
        registry.register(cold_backend_on(
            OAUTH_STATELESS_BACKEND,
            BackendConfig {
                oauth: Some(crate::config::OAuthConfig {
                    enabled: true,
                    shared_account: false,
                    scopes: vec![],
                    client_id: None,
                    client_secret: None,
                    callback_host: None,
                    callback_port: None,
                    callback_path: None,
                    token_refresh_buffer_secs: 300,
                }),
                identity_propagation: Some(stateless_propagation()),
                ..Default::default()
            },
            &oauth_wire,
        )),
        "fixture registration"
    );
    assert!(
        registry.register(cold_backend_on(
            PLAIN_STATELESS_BACKEND,
            BackendConfig {
                identity_propagation: Some(stateless_propagation()),
                ..Default::default()
            },
            &plain_wire,
        )),
        "fixture registration"
    );

    let mut configs: HashMap<String, RoutingProfileConfig> = HashMap::new();
    configs.insert(
        "open".to_string(),
        RoutingProfileConfig {
            description: "denies nothing, so authorization cannot decide this case".to_string(),
            ..Default::default()
        },
    );
    let meta = MetaMcp::new(registry)
        .with_profile_registry(ProfileRegistry::from_config(&configs, "open"));
    meta.set_identity_propagation(Arc::new(super::PerIdentityMint));
    meta.set_multi_user(true);

    let alpha_id = super::identity("alpha");

    // PREMISE, checked rather than assumed. The mint MUST succeed for this
    // caller: a resolution that returned nothing would leave the old guard
    // refusing too, and the case would pass against the defect it exists to
    // catch. This is the fixture-configuration trap that let the original
    // defect survive a complete mutation table.
    let (headers, binding) = meta
        .caller_credential_for_identity(OAUTH_STATELESS_BACKEND, Some(&alpha_id))
        .await;
    assert!(
        !headers.is_empty() && binding.is_some(),
        "premise: the caller must resolve a minted credential, or the guard \
         refuses for a reason that has nothing to do with the pool slot: \
         headers={headers:?} binding={binding:?}"
    );

    let alpha = super::listed_for(&meta, &super::super::identified_caller(&alpha_id)).await;

    // THE DISCRIMINATOR, FIRST. No `tools/list` was sent for this backend at
    // all — not one that came back empty.
    assert_eq!(
        oauth_wire.seen.lock().clone(),
        Vec::<Option<String>>::new(),
        "a backend behind one gateway-held OAuth login was fetched for an \
         identified caller on a multi-user gateway. The fill drops minted \
         headers on a `stateless` backend's shared slot, so that fetch ran \
         under the gateway's own account and its catalogue is now what every \
         caller reads"
    );
    assert!(
        !alpha.contains(&GATEWAY_ACCOUNT_TOOL.to_string()),
        "the gateway-held account's catalogue was served to an identified \
         caller: {alpha:?}"
    );

    // ANTI-VACUITY. The same propagation without the OAuth login is still
    // admitted and still fetched, so the absences above are a verdict about
    // this backend and not a gateway that answered nobody.
    assert!(
        alpha.contains(&PLAIN_STATELESS_TOOL.to_string()),
        "a `stateless` backend with no gateway-held login was omitted too, so \
         the omission above is a blanket refusal rather than the OAuth arm: \
         {alpha:?}"
    );
    assert_eq!(
        plain_wire.seen.lock().clone(),
        vec![None],
        "the admitted control was never fetched, so an empty transcript proves \
         nothing about the refused backend"
    );
}
