// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `notifications/tools/list_changed` reaches only sessions entitled to the backend.
//!
//! Its own file because `proxy.rs` is over the 800-line ceiling and the gate
//! ratchets. The fixture mirrors `webhooks/tests.rs`, whose helpers are
//! private to that module.

use std::sync::Arc;

use tokio::sync::broadcast::{Receiver, error::TryRecvError};

use crate::backend::BackendRegistry;
use crate::config::{AuthConfig, StreamingConfig};
use crate::gateway::auth::live::held_credential;
use crate::gateway::auth::{AuthState, DashboardBootstrap, ResolvedAuthConfig};
use crate::gateway::proxy::ProxyManager;
use crate::gateway::streaming::{NotificationMultiplexer, TaggedNotification};
use crate::key_server::{KeyServer, TemporaryToken};

const AUTH_ON: &str = "enabled: true
api_keys:
  - key_sha256: sha256:39a00d29356083a9c9d65c14652350d61b11d5d2e8582da510887c8e11be08c8
    name: k1
    backends: [alpha]
  - key_sha256: sha256:8fd493b2a681a4810d9fd40526a9de960deb255e7bfbb1c4d509d06d6da6ff5b
    name: k2
    backends: [beta]
";

fn authorizer(yaml: &str, key_server: Option<Arc<KeyServer>>) -> AuthState {
    let config: AuthConfig = serde_yaml::from_str(yaml).unwrap();
    AuthState {
        auth_config: Arc::new(ResolvedAuthConfig::from_config(&config)),
        key_server,
        dashboard_bootstrap: Arc::new(DashboardBootstrap::new()),
        tls_enabled: false,
    }
}

fn multiplexer(auth: AuthState) -> Arc<NotificationMultiplexer> {
    let mux = Arc::new(NotificationMultiplexer::new(
        Arc::new(BackendRegistry::new()),
        StreamingConfig::default(),
    ));
    mux.set_authorizer(auth);
    mux
}

/// Open a session the way the MCP handler does for a caller presenting `bearer`.
fn open_session(
    mux: &NotificationMultiplexer,
    id: &str,
    bearer: Option<&str>,
) -> Receiver<TaggedNotification> {
    let held = bearer.and_then(|b| {
        let mut headers = axum::http::HeaderMap::new();
        let value = format!("Bearer {b}").parse().unwrap();
        headers.insert(axum::http::header::AUTHORIZATION, value);
        held_credential(&headers)
    });
    let owner = format!("credential:{id}");
    mux.get_or_create_session_scoped(Some(id), &owner, held).1
}

fn temporary_token(backends: &[&str]) -> TemporaryToken {
    use crate::key_server::InMemoryTokenStore;
    use crate::key_server::oidc::VerifiedIdentity;
    use crate::key_server::store::TokenScopes;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    TemporaryToken {
        jti: InMemoryTokenStore::generate_jti(),
        token: InMemoryTokenStore::generate_bearer(),
        identity: VerifiedIdentity {
            subject: "sub".to_string(),
            email: "user@issuer.test".to_string(),
            name: None,
            groups: vec![],
            issuer: "https://issuer.test".to_string(),
        },
        scopes: TokenScopes {
            backends: backends.iter().map(|b| (*b).to_string()).collect(),
            tools: vec![],
            rate_limit: 0,
        },
        iat: now,
        exp: now + 3600,
        client_ip: None,
    }
}

fn assert_told(rx: &mut Receiver<TaggedNotification>, who: &str) {
    let frame = rx
        .try_recv()
        .unwrap_or_else(|e| panic!("{who} must be told: {e:?}"));
    assert_eq!(frame.data["method"], "notifications/tools/list_changed");
}

#[tokio::test]
async fn tools_list_changed_reaches_only_sessions_in_scope_for_the_changed_backend() {
    let mux = multiplexer(authorizer(AUTH_ON, None));
    let mut rx_alpha = open_session(&mux, "k1", Some("key-alpha"));
    let mut rx_beta = open_session(&mux, "k2", Some("key-beta"));

    ProxyManager::new(Arc::clone(&mux))
        .broadcast_tools_list_changed("alpha")
        .await;

    assert_told(&mut rx_alpha, "a session whose key may access alpha");
    assert_eq!(
        rx_beta.try_recv().map(|_| ()),
        Err(TryRecvError::Empty),
        "a key scoped to beta must not learn that alpha changed"
    );
}

#[tokio::test]
async fn a_revoked_session_is_not_told_about_tools_list_changes() {
    let key_server = Arc::new(KeyServer::new(crate::config::KeyServerConfig::default()));
    let kept = temporary_token(&["alpha"]);
    let revoked = temporary_token(&["alpha"]);
    let (kept_bearer, revoked_bearer) = (kept.token.clone(), revoked.token.clone());
    let revoked_jti = revoked.jti.clone();
    key_server.store.insert(kept).await;
    key_server.store.insert(revoked).await;
    let mux = multiplexer(authorizer(AUTH_ON, Some(Arc::clone(&key_server))));
    let mut rx_kept = open_session(&mux, "kept", Some(&kept_bearer));
    let mut rx_revoked = open_session(&mux, "revoked", Some(&revoked_bearer));

    assert!(key_server.store.revoke_by_jti(&revoked_jti).await);
    ProxyManager::new(Arc::clone(&mux))
        .broadcast_tools_list_changed("alpha")
        .await;

    assert_told(&mut rx_kept, "a live token");
    assert_eq!(
        rx_revoked.try_recv().map(|_| ()),
        Err(TryRecvError::Empty),
        "a token revoked after its session opened must not be told"
    );
}

#[tokio::test]
async fn with_auth_off_every_session_is_told_about_tools_list_changes() {
    let mux = multiplexer(authorizer("enabled: false\n", None));
    let mut rx_a = open_session(&mux, "a", None);
    let mut rx_b = open_session(&mux, "b", None);

    ProxyManager::new(Arc::clone(&mux))
        .broadcast_tools_list_changed("alpha")
        .await;

    assert_told(&mut rx_a, "with auth off, session a");
    assert_told(&mut rx_b, "with auth off, session b");
}
