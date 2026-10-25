// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The events observation key is the binding a call's minted
//! credential caches under, per user and per backend identity config.

use super::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode, cache_binding,
    observation_key, token_exchange::exchange_cache_key,
};
use crate::key_server::oidc::VerifiedIdentity;

fn person(subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.into(),
        email: format!("{subject}@example.com"),
        name: None,
        groups: vec!["g".into()],
        issuer: "https://idp".into(),
    }
}

fn config(strategy: PropagationStrategyKind) -> IdentityPropagationConfig {
    IdentityPropagationConfig {
        strategy,
        audience: "https://mail".into(),
        required: true,
        session_mode: SessionMode::PerUser,
        token_exchange_endpoint: Some("https://sts/token".into()),
        token_exchange_scope: Some("mail.read".into()),
    }
}

#[test]
fn signed_assertion_and_passthrough_observe_by_the_call_binding() {
    for kind in [
        PropagationStrategyKind::SignedAssertion,
        PropagationStrategyKind::Passthrough,
    ] {
        let p = person("p");
        assert_eq!(
            observation_key(&config(kind), &p),
            Some(cache_binding(&p.stable_actor_id(), "https://mail")),
            "{kind:?}"
        );
    }
}

#[test]
fn token_exchange_observes_by_its_exchange_key() {
    let p = person("p");
    assert_eq!(
        observation_key(&config(PropagationStrategyKind::TokenExchange), &p),
        Some(exchange_cache_key(
            &p.stable_actor_id(),
            "https://mail",
            "https://sts/token",
            "mail.read"
        ))
    );
    let mut wider = config(PropagationStrategyKind::TokenExchange);
    wider.token_exchange_scope = Some("mail.send".into());
    assert_ne!(
        observation_key(&wider, &p),
        observation_key(&config(PropagationStrategyKind::TokenExchange), &p),
        "a scope change is a new observation"
    );
}

#[test]
fn two_users_never_share_an_observation() {
    for kind in [
        PropagationStrategyKind::SignedAssertion,
        PropagationStrategyKind::Passthrough,
        PropagationStrategyKind::TokenExchange,
    ] {
        assert_ne!(
            observation_key(&config(kind), &person("p")),
            observation_key(&config(kind), &person("q")),
            "{kind:?}"
        );
    }
}

#[test]
fn an_audience_change_is_a_new_observation() {
    let mut other = config(PropagationStrategyKind::SignedAssertion);
    other.audience = "https://calendar".into();
    assert_ne!(
        observation_key(&other, &person("p")),
        observation_key(
            &config(PropagationStrategyKind::SignedAssertion),
            &person("p")
        )
    );
}

#[test]
fn a_vault_backend_observes_by_account_not_identity() {
    assert_eq!(
        observation_key(&config(PropagationStrategyKind::Vault), &person("p")),
        None
    );
}
