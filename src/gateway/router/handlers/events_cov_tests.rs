// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8195: `Presented::credential` for a key-server token and a dashboard
//! session — the binding each is re-checked against at delivery, and the
//! expiry (a dashboard session's capped at one idle timeout from now).

use super::*;
use crate::gateway::auth::AuthenticatedClient;

/// A client that authenticated with `kind`.
fn client(kind: CredentialKind) -> AuthenticatedClient {
    AuthenticatedClient {
        name: "alice".to_owned(),
        rate_limit: 0,
        backends: vec!["*".to_owned()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        principal: crate::gateway::auth::principal_of("secret"),
        quota_principal: None,
        authenticated: true,
        credential_kind: kind,
    }
}

/// What a request presented: `facts`, a session digest, and nothing else.
fn presented(facts: Option<CredentialFacts>, session_sha256: Option<String>) -> Presented {
    Presented {
        facts,
        identity: None,
        session_sha256,
        bearer_sha256: None,
    }
}

/// Facts that name `jti` and an expiry a day out.
fn facts(jti: Option<&str>) -> CredentialFacts {
    CredentialFacts {
        expires_at: Some(
            crate::clock::utc_now().expect("the test host's clock reads after 1970")
                + crate::duration_bound::delta!(days, 1),
        ),
        jti: jti.map(str::to_owned),
        issued_at: None,
        provider_sha256: None,
    }
}

/// A key-server token binds its `jti` and keeps its own expiry; no `jti`, no binding.
#[tokio::test(flavor = "multi_thread")]
async fn a_key_server_subscription_binds_the_token_jti_and_keeps_its_expiry() {
    // GIVEN
    let (state, _dir) = crate::gateway::router::tests::test_router_app_state().await;
    let caller = client(CredentialKind::KeyServerToken);
    let with = facts(Some("jti-7f3a"));
    // WHEN
    let credential = presented(Some(with.clone()), None)
        .credential(Some(&caller), &state)
        .expect("a bounded idle timeout");
    // THEN
    assert_eq!(
        credential,
        crate::events::Credential {
            kind: CredentialKind::KeyServerToken,
            principal: caller.principal.clone(),
            api_key: None,
            expires_at: with.expires_at,
            binding: Some(LiveBinding::KeyServerToken {
                jti: "jti-7f3a".to_owned()
            }),
        }
    );
    let unbound = presented(Some(facts(None)), None)
        .credential(Some(&caller), &state)
        .expect("a bounded idle timeout");
    assert_eq!(unbound.binding, None, "no jti, no binding");
}

/// A dashboard session binds its digest and expires one idle timeout out, not at the facts'.
#[tokio::test(flavor = "multi_thread")]
async fn a_dashboard_subscription_binds_the_session_and_expires_one_idle_timeout_out() {
    // GIVEN: a 600 s idle timeout and facts claiming a day
    let (state, _dir) = crate::gateway::router::tests::test_router_app_state().await;
    let mut config = (*state.live_config.get()).clone();
    config.auth.dashboard_session.idle_timeout_secs = 600;
    state.live_config.set(config);
    let caller = client(CredentialKind::DashboardSession);
    let digest = crate::hashing::sha256_hex(b"session-handle");
    let idle = crate::duration_bound::delta!(seconds, 600);
    // WHEN
    let before = crate::clock::utc_now().expect("the test host's clock reads after 1970");
    let credential = presented(Some(facts(Some("ignored"))), Some(digest.clone()))
        .credential(Some(&caller), &state)
        .expect("a bounded idle timeout");
    let after = crate::clock::utc_now().expect("the test host's clock reads after 1970");
    // THEN
    assert_eq!(credential.kind, CredentialKind::DashboardSession);
    assert_eq!(credential.principal, caller.principal);
    assert_eq!(credential.api_key, None);
    assert_eq!(
        credential.binding,
        Some(LiveBinding::DashboardSession {
            session_sha256: digest
        })
    );
    let expires_at = credential.expires_at.expect("a session always expires");
    assert!(
        before + idle <= expires_at && expires_at <= after + idle,
        "{expires_at} is one idle timeout from now, not the facts' day"
    );
    let unbound = presented(None, None)
        .credential(Some(&caller), &state)
        .expect("a bounded idle timeout");
    assert_eq!(unbound.binding, None, "no session cookie, no binding");
    assert!(unbound.expires_at.is_some(), "the idle cap still applies");
}
