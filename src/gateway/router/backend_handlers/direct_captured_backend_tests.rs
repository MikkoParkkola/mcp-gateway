// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7804: the direct route decides on the backend it captured, not on
//! whatever the registry holds under that name a moment later. A reload that
//! swaps the backend between the capture (`route`) and the identity stage must
//! not change which backend's credential rules and OAuth-isolation rule apply
//! to the request, because the request is dispatched through the captured one.

use std::sync::Arc;
use std::time::Duration;

use super::direct_caller::{Caller, Route};
use super::direct_preflight::{Preflight, propagate_identity};
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig, OAuthConfig};
use crate::gateway::router::direct_guards_fixture::{Answer, Fx, fixture};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::protocol::RequestId;

fn anonymous() -> Caller {
    Caller {
        generation: crate::config_reload::LiveConfig::new(crate::config::Config::default())
            .generation(),
        client: None,
        cert_identity: None,
        oauth_agent_identity: None,
        proven: None,
        slot: None,
        verified_identity: None,
        inbound_headers: axum::http::HeaderMap::new(),
        grant_subject: None,
        spend_key: String::new(),
        agent_identity: None,
    }
}

fn guarded() -> Preflight {
    Preflight {
        retry: crate::protocol::mrtr::RetryFields::default(),
        chain_nonce: None,
        signing_scope: crate::gateway::meta_mcp::signing::SigningScope::InvokeOnly,
        signs: false,
        signing_nonce: None,
        challenge: None,
        isolation_guarded: true,
    }
}

fn backend(config: BackendConfig) -> Arc<Backend> {
    Arc::new(Backend::new(
        "alpha",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

/// Replace `alpha` in the registry, as a config reload does.
fn reload(fx: &Fx, replacement: Arc<Backend>) {
    assert!(fx.state.backends.remove("alpha"), "alpha was registered");
    assert!(
        fx.state.backends.register(replacement),
        "the reload registers the replacement"
    );
}

async fn resolve(fx: &Fx, captured: &Arc<Backend>) -> Result<(), u16> {
    let route = Route {
        backend: Arc::clone(captured),
        session_id: None,
    };
    propagate_identity(
        &fx.state,
        "alpha",
        &anonymous(),
        &route,
        &guarded(),
        &RequestId::Number(1),
    )
    .await
    .map(|_| ())
    .map_err(|refused| refused.status.as_u16())
}

fn shared_login() -> BackendConfig {
    BackendConfig {
        oauth: Some(OAuthConfig {
            enabled: true,
            scopes: vec![],
            client_id: None,
            client_secret: None,
            callback_host: None,
            callback_port: None,
            callback_path: None,
            token_refresh_buffer_secs: Some(300),
            shared_account: false,
        }),
        ..BackendConfig::default()
    }
}

fn required_propagation() -> BackendConfig {
    BackendConfig {
        identity_propagation: Some(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "alpha".to_string(),
            required: true,
            session_mode: SessionMode::PerUser,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        ..BackendConfig::default()
    }
}

/// ADR-008 INV-2 against the captured instance. The captured backend serves no
/// personal login, so the multi-user guard passes for it; the replacement a
/// reload registered under the same name does serve one. Mutant: the guard
/// looked up by name judges the replacement and refuses a request that the
/// captured backend would have served (or, the other way round, admits one the
/// captured backend must refuse). The control shows the guard is live.
#[tokio::test]
async fn the_oauth_isolation_guard_judges_the_captured_backend() {
    let fx = fixture(Answer::Ok, |meta| meta.set_multi_user(true)).await;
    let captured = fx.state.backends.get("alpha").expect("alpha is registered");
    let personal = backend(shared_login());
    reload(&fx, Arc::clone(&personal));

    assert_eq!(
        resolve(&fx, &personal).await,
        Err(403),
        "control: a shared personal login is refused on a multi-user gateway"
    );
    assert_eq!(
        resolve(&fx, &captured).await,
        Ok(()),
        "the captured backend has no personal login: the reload must not decide for it"
    );
}

/// The credential rules (a `required` propagation refuses an anonymous caller)
/// are the captured backend's own. Mutant: resolving the credential by name
/// applies the replacement's rules to the request dispatched through the
/// captured one.
#[tokio::test]
async fn the_credential_rules_are_the_captured_backends() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let captured = fx.state.backends.get("alpha").expect("alpha is registered");
    let strict = backend(required_propagation());
    reload(&fx, Arc::clone(&strict));

    assert_eq!(
        resolve(&fx, &strict).await,
        Err(403),
        "control: a required propagation refuses an anonymous caller"
    );
    assert_eq!(
        resolve(&fx, &captured).await,
        Ok(()),
        "the captured backend has no propagation: the reload must not decide for it"
    );
}

/// The notification arm resolves the credential on the backend it forwards
/// through. Mutant: resolving by name applies a reload's replacement rules to a
/// notification sent through the captured backend.
#[tokio::test]
async fn the_notification_arm_resolves_on_the_captured_backend() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let captured = fx.state.backends.get("alpha").expect("alpha is registered");
    let strict = backend(required_propagation());
    reload(&fx, Arc::clone(&strict));
    let caller = anonymous();

    let refused = super::notification_key::resolve(
        &fx.state,
        &strict,
        "alpha",
        &caller.inbound_headers,
        caller.proof(),
        None,
    )
    .await;
    assert!(refused.is_err(), "control: a required propagation refuses");

    let served = super::notification_key::resolve(
        &fx.state,
        &captured,
        "alpha",
        &caller.inbound_headers,
        caller.proof(),
        None,
    )
    .await;
    assert!(
        served.is_ok(),
        "the captured backend has no propagation: the reload must not decide for it"
    );
}

/// MIK-8063: an A2A agent's question on this route is bound to the caller who
/// was asked, by this route itself. The continuation seal (MIK-8078) binds the
/// same callers, so no end-to-end row can tell the two apart: every caller the
/// seal leaves unbound gets no continuation at all. This row pins the inner
/// binding. Mutant: dropping it leaves an A2A key holder's `identity_key` unset.
#[cfg(feature = "a2a")]
#[tokio::test]
async fn an_a2a_question_on_this_route_is_bound_to_the_key_holder() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let agent = backend(BackendConfig {
        transport: crate::config::TransportConfig::A2a {
            a2a_url: "http://127.0.0.1:9/".into(),
            a2a_agent_card_path: None,
        },
        ..BackendConfig::default()
    });
    let route = Route {
        backend: agent,
        session_id: None,
    };
    let key_of = |principal: Option<&str>| {
        let mut caller = anonymous();
        caller.client = principal.map(|principal| crate::gateway::auth::AuthenticatedClient {
            quota_principal: None,
            // One display name for every key holder: binding by name would
            // make them one caller.
            name: "key-holder".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            // MIK-6704.IDENT.1a: a synthetic fixture, not an authorization path.
            principal: crate::gateway::record_principal::InternalPrincipal::new(
                principal.to_string(),
            ),
            authenticated: true,
            credential_kind: crate::security::audit::CredentialKind::ApiKey,
        });
        caller
    };
    let mut keys = Vec::new();
    for principal in [Some("alice-digest"), Some("bob-digest"), None] {
        let propagation = propagate_identity(
            &fx.state,
            "alpha",
            &key_of(principal),
            &route,
            &guarded(),
            &RequestId::Number(1),
        )
        .await
        .unwrap_or_else(|refused| panic!("refused with {}", refused.status));
        keys.push(propagation.identity_key);
    }
    assert_eq!(
        keys[0].as_deref(),
        Some(crate::hashing::sha256_hex(b"a2a-client:alice-digest").as_str()),
        "the key holder who was asked"
    );
    assert_eq!(
        keys[1].as_deref(),
        Some(crate::hashing::sha256_hex(b"a2a-client:bob-digest").as_str()),
        "another key holder under the same name is another caller"
    );
    assert_eq!(keys[2], None, "an anonymous caller binds to nothing");
}

/// D-a2a premise (MIK-8434): an A2A key holder on an optional
/// `SignedAssertion` backend has no verified end-user identity, so the mint
/// falls back to static credentials, and the A2A override still binds
/// `identity_key` to the key holder, but the propagation stays unproven
/// (mutant M-a2a: the A2A key read as a proof).
#[cfg(feature = "a2a")]
#[tokio::test]
async fn an_unminted_a2a_key_holder_is_bound_but_not_proven() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let mut config = required_propagation();
    if let Some(cfg) = config.identity_propagation.as_mut() {
        cfg.required = false;
    }
    config.transport = crate::config::TransportConfig::A2a {
        a2a_url: "http://127.0.0.1:9/".into(),
        a2a_agent_card_path: None,
    };
    let route = Route {
        backend: backend(config),
        session_id: None,
    };
    let mut caller = anonymous();
    caller.client = Some(crate::gateway::auth::AuthenticatedClient {
        quota_principal: None,
        name: "key-holder".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        // MIK-6704.IDENT.1a: a synthetic fixture, not an authorization path.
        principal: crate::gateway::record_principal::InternalPrincipal::new(
            "alice-digest".to_string(),
        ),
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    });
    let propagation = propagate_identity(
        &fx.state,
        "alpha",
        &caller,
        &route,
        &guarded(),
        &RequestId::Number(1),
    )
    .await
    .unwrap_or_else(|refused| panic!("premise: the optional fallback refused: {}", refused.status));
    assert_eq!(
        propagation.identity_key.as_deref(),
        Some(crate::hashing::sha256_hex(b"a2a-client:alice-digest").as_str()),
        "premise: the A2A override bound the key holder"
    );
    assert!(
        propagation.headers.is_empty() && !propagation.attempted,
        "premise: the static fallback, not a mint: {:?}",
        propagation.headers
    );
    // The A2A binding is not a proof of the caller's account.
    assert_eq!(
        propagation
            .unproven
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some(
            "Configuration error: identity propagation minted no credential for backend \
             'alpha'; a stored result is not served without one"
        ),
        "D-a2a: the A2A key read as a proof"
    );
}

/// D-a2a end to end (mutant M-a2a): the A2A key holder's binding does not
/// get an unminted keyed retry past the refusal. The first call to the real
/// A2A stub agent is answered; its 7a entry then ages out while the 7b
/// execution store keeps it, so the same key replays from 7b: refused with
/// the unminted refusal, and the agent is not reached again.
#[cfg(all(feature = "a2a", feature = "firewall"))]
#[tokio::test]
async fn an_unminted_a2a_key_holder_is_not_served_a_7b_replay() {
    use crate::gateway::router::direct_guards_fixture::{fixture_built, post_direct};
    use crate::gateway::router::direct_guards_fixture_a2a::{A2A_BACKEND, A2aAnswer, register_a2a};
    use std::sync::atomic::Ordering;

    let cache = Arc::new(crate::idempotency::IdempotencyCache::new());
    let installed = Arc::clone(&cache);
    let fx = fixture_built(Answer::Ok, move |mut meta| {
        meta.enable_idempotency(installed, Duration::from_secs(300));
        meta
    })
    .await;
    let optional = IdentityPropagationConfig {
        strategy: PropagationStrategyKind::SignedAssertion,
        audience: A2A_BACKEND.to_string(),
        required: false,
        session_mode: SessionMode::PerUser,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    };
    let sends = register_a2a(&fx, A2aAnswer::Text("agent-answer"), Some(optional)).await;
    let call = async || {
        let args = serde_json::json!({"message": "hi"});
        post_direct(
            &fx,
            A2A_BACKEND,
            "k-std",
            "send_message",
            args,
            Some("a2a-k"),
            None,
        )
        .await
    };
    let (status, first) = call().await;
    assert_eq!(status, 200, "premise: {first}");
    assert!(
        first.to_string().contains("agent-answer"),
        "premise: the agent answered: {first}"
    );
    assert_eq!(sends.load(Ordering::SeqCst), 1, "premise: one SendMessage");
    // Past the cache's 24-hour completed lifetime: a forced 7a miss.
    cache.advance_for_test(Duration::from_secs(25 * 60 * 60));
    let (status, again) = call().await;
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "D-a2a e2e: the agent was reached again: {again}"
    );
    assert_eq!(
        (status.as_u16(), again.get("error")),
        (
            200,
            Some(&serde_json::json!({
                "code": -32603,
                "message": "Configuration error: identity propagation minted no credential \
                            for backend 'alpha-a2a'; a stored result is not served without one"
            }))
        ),
        "D-a2a e2e: the A2A binding got the stored result past the refusal: {again}"
    );
}

/// The direct route keeps the credential it resolved in the zeroizing holder
/// the lender uses: the type it stores is pinned here, so a change that hands
/// the secret to a plain `Vec` fails to build.
#[test]
fn a_direct_route_credential_is_wiped_on_drop() {
    type Held = zeroize::Zeroizing<Vec<(String, String)>>;
    type Propagation = super::direct_preflight::Propagation;
    fn stored(propagation: &Propagation) -> &Held {
        &propagation.headers
    }
    let pinned: for<'a> fn(&'a Propagation) -> &'a Held = stored;
    let empty: Held = Held::default();
    assert!(
        empty.is_empty(),
        "premise: the holder type is the zeroizing one"
    );
    let _ = pinned;
}
