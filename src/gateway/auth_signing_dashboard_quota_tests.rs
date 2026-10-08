// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::Service;

use super::{
    AuthState, AuthenticatedClient, DashboardBootstrap, ResolvedAuthConfig, SESSION_COOKIE,
    auth_middleware,
};
use crate::config::AuthConfig;
use crate::security::message_signing::NonceStore;

const PRIMARY: &str = "dashboard-primary-0123456789abcdef";
const OPS: &str = "dashboard-ops-0123456789abcdef";
/// The production per-principal admission limit (`NonceStore::new`).
const PRINCIPAL_LIMIT: usize = 10_000;
/// A public path, so an unauthenticated probe reaches the handler and the
/// identity it was handed can be read, instead of being answered 401.
const PROBE_PATH: &str = "/mcp";
const REPLAY_WINDOW: Duration = Duration::from_secs(300);

/// Real resolved auth over a real bootstrap, with nothing hand-built.
fn auth_state(enabled: bool) -> (AuthState, Arc<DashboardBootstrap>) {
    let ops_digest = crate::config::api_key_digest_spec(OPS.as_bytes());
    let config: AuthConfig = serde_json::from_value(serde_json::json!({
        "enabled": enabled,
        "bearer_token": PRIMARY,
        "public_paths": ["/health", PROBE_PATH],
        "api_keys": [{"key_sha256": ops_digest, "name": "ops", "admin": true}]
    }))
    .expect("auth config fixture deserializes");
    let bootstrap = Arc::new(DashboardBootstrap::new());
    (
        AuthState {
            auth_config: Arc::new(ResolvedAuthConfig::from_config(&config)),
            key_server: None,
            dashboard_bootstrap: Arc::clone(&bootstrap),
            tls_enabled: false,
            live_config: Arc::new(crate::config_reload::LiveConfig::new(
                crate::config::Config::default(),
            )),
            agent_auth: crate::gateway::oauth::AgentAuthState::new(
                false,
                std::sync::Arc::default(),
            ),
        },
        bootstrap,
    )
}

/// Drive the real middleware and return the identity it published.
///
/// `label` travels as the caller-chosen audit header, which must never
/// reach the quota decision.
async fn identity_for_request(
    state: &AuthState,
    cookie: Option<&str>,
    bearer: Option<&str>,
    label: &str,
) -> AuthenticatedClient {
    let seen: Arc<Mutex<Option<AuthenticatedClient>>> = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&seen);
    let mut router = axum::Router::new()
        .route(
            PROBE_PATH,
            axum::routing::get(
                move |axum::Extension(client): axum::Extension<AuthenticatedClient>| {
                    let sink = Arc::clone(&sink);
                    async move {
                        *sink.lock().expect("probe sink") = Some(client);
                        StatusCode::OK
                    }
                },
            ),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let mut builder = Request::builder()
        .uri(PROBE_PATH)
        .header("x-agent-id", label);
    if let Some(handle) = cookie {
        builder = builder.header(header::COOKIE, format!("{SESSION_COOKIE}={handle}"));
    }
    if let Some(credential) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {credential}"));
    }
    let request = builder.body(Body::empty()).expect("probe request builds");

    let response = router
        .call(request)
        .await
        .expect("middleware is infallible");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the probe was not admitted, so no identity was published"
    );
    seen.lock()
        .expect("probe sink")
        .clone()
        .expect("the middleware published no identity")
}

async fn identity_for(state: &AuthState, cookie: Option<&str>) -> AuthenticatedClient {
    identity_for_request(state, cookie, None, "caller-label").await
}

/// The mapping the production caller performs: the authenticated bucket
/// when the transport published one, the shared anonymous bucket otherwise.
fn admit(store: &NonceStore, identity: &AuthenticatedClient, nonce: &str) -> crate::Result<()> {
    identity.quota_principal.as_ref().map_or_else(
        || store.check_and_register(nonce),
        |principal| store.check_and_register_for_principal(nonce, principal.as_store_key()),
    )
}

/// Exhaust one identity's bucket. Direct registration: no I/O, and it is
/// the production limit rather than a fixture-shrunk one.
fn fill(store: &NonceStore, identity: &AuthenticatedClient, tag: &str) {
    for i in 0..PRINCIPAL_LIMIT {
        admit(store, identity, &format!("{tag}-{i}")).expect("a bucket admits its own limit");
    }
}

fn refusal(result: crate::Result<()>) -> String {
    result
        .expect_err("admission should have been refused")
        .to_string()
}

#[tokio::test]
async fn a_validated_dashboard_session_carries_one_authenticated_quota_bucket() {
    let (state, bootstrap) = auth_state(true);
    let first = bootstrap.issue_session();
    let second = bootstrap.issue_session();
    // Compared, never printed: a failing `assert_ne!` would put both live
    // session handles in the test output.
    assert!(first != second, "two browsers, two handles");

    let one = identity_for_request(&state, Some(&first), None, "browser-one").await;
    let two = identity_for_request(&state, Some(&second), None, "browser-two").await;
    let relabelled = identity_for_request(&state, Some(&first), None, "browser-two").await;

    for identity in [&one, &two] {
        assert!(
            identity.authenticated,
            "a session validated against this process's store is a credential"
        );
        assert!(identity.admin, "the dashboard session is an admin session");
        assert!(
            identity.quota_principal.is_some(),
            "an operator's own dashboard must not draw on the anonymous \
             bucket that any unauthenticated caller can fill"
        );
    }
    assert_eq!(
        one.quota_principal, two.quota_principal,
        "every session of one gateway is the same operator, so they share \
         one bucket — a per-handle bucket would let a browser mint quota by \
         reloading the dashboard"
    );
    assert_eq!(
        one.quota_principal, relabelled.quota_principal,
        "a caller-chosen label is not an identity"
    );
}

#[tokio::test]
async fn a_dashboard_bucket_is_not_a_static_credential_bucket() {
    let (state, bootstrap) = auth_state(true);
    let session = identity_for(&state, Some(&bootstrap.issue_session())).await;
    let bearer = identity_for_request(&state, None, Some(PRIMARY), "ops").await;
    let ops = identity_for_request(&state, None, Some(OPS), "ops").await;

    assert!(bearer.quota_principal.is_some() && ops.quota_principal.is_some());
    assert_ne!(
        session.quota_principal, bearer.quota_principal,
        "the dashboard must not spend the configured bearer's quota"
    );
    assert_ne!(session.quota_principal, ops.quota_principal);
    assert_ne!(bearer.quota_principal, ops.quota_principal);
}

#[tokio::test]
async fn a_cookie_this_process_did_not_issue_mints_no_quota_authority() {
    let (state, _bootstrap) = auth_state(true);

    for cookie in [None, Some("not-a-handle-this-process-issued"), Some("")] {
        let identity = identity_for(&state, cookie).await;
        assert!(
            identity.quota_principal.is_none(),
            "an unvalidated cookie must leave the caller anonymous"
        );
        assert!(!identity.authenticated);
        assert!(!identity.admin);
    }

    // Auth disabled: the handle is genuinely this process's, and still
    // nothing validated it, so it may not mint authority.
    let (disabled, disabled_bootstrap) = auth_state(false);
    let handle = disabled_bootstrap.issue_session();
    let anonymous = identity_for(&disabled, Some(&handle)).await;
    assert!(
        anonymous.quota_principal.is_none(),
        "an auth-disabled gateway authenticates nobody, so a cookie is a string"
    );
    assert!(!anonymous.authenticated);
}

#[tokio::test]
async fn an_anonymous_flood_cannot_starve_the_operator_dashboard() {
    let (state, bootstrap) = auth_state(true);
    let anonymous = identity_for(&state, None).await;
    let session = identity_for(&state, Some(&bootstrap.issue_session())).await;
    let store = NonceStore::new(REPLAY_WINDOW);

    fill(&store, &anonymous, "anon");
    assert!(
        refusal(admit(&store, &anonymous, "anon-over")).contains("Signing nonce capacity exceeded"),
        "the anonymous bucket is not full, so this proves nothing"
    );

    admit(&store, &session, "dashboard-fresh")
        .expect("a validated operator session must hold capacity a public flood cannot spend");
}

#[tokio::test]
async fn dashboard_sessions_share_a_bucket_and_never_a_private_namespace() {
    let (state, bootstrap) = auth_state(true);
    let first = identity_for(&state, Some(&bootstrap.issue_session())).await;
    let second = identity_for(&state, Some(&bootstrap.issue_session())).await;
    let bearer = identity_for_request(&state, None, Some(PRIMARY), "ops").await;
    let store = NonceStore::new(REPLAY_WINDOW);

    fill(&store, &first, "dash");
    assert!(
        refusal(admit(&store, &second, "second-fresh")).contains("Signing nonce capacity exceeded"),
        "a second browser must not double the operator's quota"
    );
    admit(&store, &bearer, "bearer-fresh").expect("a static credential owns a bucket of its own");
    assert!(
        refusal(admit(&store, &bearer, "dash-0")).contains("Nonce replay detected"),
        "nonce uniqueness is global: a bucket is capacity, not a namespace"
    );
}
