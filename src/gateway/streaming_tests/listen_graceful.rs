// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7798 R12 (H3): when the server closes a `subscriptions/listen` stream,
//! the graceful end goes only to a credential that still authenticates. A dead
//! one gets nothing and learns of the refusal when it re-subscribes.

use super::*;
use crate::key_server::store::TokenStore as _;

fn bearer(token: &str) -> Option<HeldCredential> {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    crate::gateway::auth::live::held_credential(&headers)
}

/// A key-server temporary token, as `auth_live`'s rows mint one.
fn temporary_token() -> crate::key_server::TemporaryToken {
    use crate::key_server::InMemoryTokenStore;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    crate::key_server::TemporaryToken {
        jti: InMemoryTokenStore::generate_jti(),
        token: InMemoryTokenStore::generate_bearer(),
        identity: crate::key_server::oidc::VerifiedIdentity {
            subject: "sub".to_string(),
            email: "user@issuer.test".to_string(),
            name: None,
            groups: vec![],
            issuer: "https://issuer.test".to_string(),
        },
        scopes: crate::key_server::store::TokenScopes {
            backends: vec!["alpha".to_string()],
            tools: vec![],
            rate_limit: 0,
        },
        iat: now,
        exp: now + 3600,
        client_ip: None,
    }
}

/// Authentication on, with `key_server` issuing the tokens.
fn authorizer(key_server: Arc<crate::key_server::KeyServer>) -> AuthState {
    let config = crate::config::AuthConfig {
        enabled: true,
        ..crate::config::AuthConfig::default()
    };
    AuthState {
        auth_config: Arc::new(crate::gateway::auth::ResolvedAuthConfig::from_config(
            &config,
        )),
        key_server: Some(key_server),
        dashboard_bootstrap: Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        tls_enabled: false,
        live_config: Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        agent_auth: crate::gateway::oauth::AgentAuthState::new(false, Arc::default()),
    }
}

/// The whole body of a listen stream admitted while its token was live, whose
/// token is revoked when `revoke`, and which the server then closes.
async fn closed_listen_body(revoke: bool) -> String {
    use crate::gateway::outbound::{RejectionAudit, StreamJudge};
    use crate::gateway::subscription_registry::SubscriptionRegistry;
    use crate::protocol::subscriptions::{ListenRequest, SubscriptionId};
    use axum::response::IntoResponse as _;

    let key_server = Arc::new(crate::key_server::KeyServer::new(
        crate::config::KeyServerConfig::default(),
    ));
    let token = temporary_token();
    let (credential, jti) = (bearer(&token.token), token.jti.clone());
    key_server.store.insert(token).await;
    let registry = SubscriptionRegistry::new(4, authorizer(Arc::clone(&key_server)));
    let listener = registry
        .subscribe_as(credential)
        .await
        .expect("admitted while the token is live");
    let params = json!({ "notifications": { "toolsListChanged": true } });
    let filter = ListenRequest::from_params(Some(&params)).expect("a listen filter");
    let subscription = SubscriptionId::of_request(crate::protocol::RequestId::Number(7));
    let acknowledgement = filter.acknowledgement(&subscription);
    let response = crate::gateway::streaming::subscription_stream(
        listener,
        filter,
        subscription,
        acknowledgement,
        Duration::from_secs(3600),
        StreamJudge::new(None, Arc::new(RejectionAudit::new(None, 1)), None),
        None,
        None,
    )
    .into_response();
    if revoke {
        assert!(key_server.store.revoke_by_jti(&jti).await);
    }
    // The registry holds the only sender: dropping it is the server closing.
    drop(registry);
    let bytes = tokio::time::timeout(
        Duration::from_secs(5),
        axum::body::to_bytes(response.into_body(), usize::MAX),
    )
    .await
    .expect("a closed listen stream ends")
    .expect("the body reads");
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn a_closed_listen_ends_gracefully_only_for_a_live_credential() {
    let live = closed_listen_body(false).await;
    assert_eq!(
        live.matches("data: ").count(),
        2,
        "a live credential reads the acknowledgement and the graceful end: {live}"
    );

    let dead = closed_listen_body(true).await;
    assert_eq!(
        dead.matches("data: ").count(),
        1,
        "a revoked credential reads only the acknowledgement it was sent while live: {dead}"
    );
}
