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
        client: None,
        cert_identity: None,
        oauth_agent_identity: None,
        proven: None,
        slot: None,
        verified_identity: None,
        inbound_headers: axum::http::HeaderMap::new(),
        grant_subject: None,
        spend_key: String::new(),
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
    .map_err(|(status, _)| status.as_u16())
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
            token_refresh_buffer_secs: 300,
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
            principal: principal.to_string(),
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
        .unwrap_or_else(|(status, _)| panic!("refused with {status}"));
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
