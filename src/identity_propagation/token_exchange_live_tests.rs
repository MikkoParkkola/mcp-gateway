// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! End-to-end integration tests for [`super::TokenExchangeStrategy`]
//! (MIK-6729) against the gateway's OWN `/auth/token` handler
//! ([`crate::key_server::handler`]) — no mock HTTP server, no stubbed
//! verifier. This is the same code path an operator hits by pointing a
//! backend's `token_exchange_endpoint` at `https://<gateway>/auth/token`.
//!
//! # Why the gateway's own token endpoint doubles as the STS
//!
//! [`TokenExchangeStrategy`] mints its RFC 8693 `subject_token` by reusing
//! [`super::SignedAssertionStrategy::mint`] verbatim — a gateway-signed ES256
//! JWT with `iss: "mcp-gateway"`. The key server's `/auth/token` handler
//! verifies an inbound `subject_token` as an OIDC ID token via
//! [`crate::key_server::oidc::OidcVerifier`]. Configuring that verifier with
//! an OIDC "provider" whose issuer is `"mcp-gateway"` and whose `jwks_uri`
//! serves the SAME [`GatewayKeyPair`]'s public key ([`jwks_handler`]) makes
//! the gateway trust its own signed assertions as a subject token — closing
//! the loop entirely in-process, with a real HTTP round trip on a real
//! ephemeral TCP port, and zero mocks.

use std::sync::Arc;

use axum::{Router, routing::get};
use tokio::net::TcpListener;

use crate::config::{
    KeyServerConfig, KeyServerPolicyConfig, KeyServerProviderConfig, PolicyMatchConfig,
    PolicyScopesConfig,
};
use crate::gateway::oauth::{GatewayKeyPair, jwks_handler};
use crate::identity_propagation::{BackendDescriptor, IdentityPropagation, TokenExchangeStrategy};
use crate::key_server::oidc::VerifiedIdentity;
use crate::key_server::policy::PolicyEngine;
use crate::key_server::{InMemoryTokenStore, KeyServer, OidcVerifier, handler::key_server_routes};

/// Issuer value [`super::SignedAssertionStrategy`] always stamps into the
/// minted subject-token assertion (`SignedAssertionStrategy::ISSUER`). The
/// key-server OIDC provider config below MUST use the same value so
/// `OidcVerifier::verify` looks up the right provider by `iss`.
const GATEWAY_ASSERTION_ISSUER: &str = "mcp-gateway";

/// Everything the test needs to talk to the in-process gateway token server:
/// the bound address, the join handle (so a test can kill the server to
/// prove a cache hit needs no network), and the signing key shared between
/// the JWKS endpoint and the strategy under test.
struct LiveServer {
    addr: std::net::SocketAddr,
    server: tokio::task::JoinHandle<()>,
    key_server: Arc<KeyServer>,
}

impl LiveServer {
    /// Boot a real axum server exposing both the gateway's own
    /// `/auth/token` exchange handler and its `/.well-known/jwks.json` — the
    /// two endpoints a `TokenExchangeStrategy` round trip actually needs.
    async fn start(key: &Arc<GatewayKeyPair>, policies: Vec<KeyServerPolicyConfig>) -> Self {
        let config = KeyServerConfig {
            enabled: true,
            oidc: vec![KeyServerProviderConfig {
                issuer: GATEWAY_ASSERTION_ISSUER.to_string(),
                // Filled in with the real bound address below, once known —
                // see the `jwks_uri` patch after `local_addr()`.
                jwks_uri: Some(String::new()),
                discovery_url: None,
                auto_discover: false,
                audiences: Vec::new(),
                allowed_domains: Vec::new(),
            }],
            policies,
            ..KeyServerConfig::default()
        };

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local_addr");

        // Now that the port is known, point the provider's jwks_uri at this
        // same in-process server — a real HTTP fetch, not an injected
        // document. `OidcVerifier::with_http_client` (test-only) swaps in a
        // plain (non-`https_only`) client since this is a loopback HTTP
        // server, mirroring `JwksCache::with_http_client`'s MIK-6729 rationale.
        let mut config = config;
        config.oidc[0].jwks_uri = Some(format!("http://{addr}/.well-known/jwks.json"));

        let key_server = Arc::new(KeyServer {
            store: Arc::new(InMemoryTokenStore::new()),
            oidc: Arc::new(OidcVerifier::with_http_client(
                config.oidc.clone(),
                reqwest::Client::new(),
            )),
            policy: Arc::new(PolicyEngine::new(config.policies.clone())),
            config,
        });

        let jwks_router = Router::new()
            .route("/.well-known/jwks.json", get(jwks_handler))
            .with_state(Arc::clone(key));
        let app = key_server_routes(Arc::clone(&key_server)).merge(jwks_router);

        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("in-process test server");
        });

        Self {
            addr,
            server,
            key_server,
        }
    }

    fn token_exchange_endpoint(&self) -> String {
        format!("http://{}/auth/token", self.addr)
    }

    /// Kill the server task outright — used to prove a second `propagate()`
    /// call is served from cache rather than silently retrying the network.
    fn kill(self) {
        self.server.abort();
    }
}

fn identity(email: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alice-subject".to_string(),
        email: email.to_string(),
        name: None,
        groups: vec!["eng".to_string()],
        issuer: "https://corp-idp.example".to_string(),
    }
}

fn allow_all_policy() -> KeyServerPolicyConfig {
    KeyServerPolicyConfig {
        match_criteria: PolicyMatchConfig {
            domain: Some("corp.example".to_string()),
            issuer: None,
            email: None,
            group: None,
        },
        scopes: PolicyScopesConfig {
            backends: vec!["*".to_string()],
            tools: vec!["*".to_string()],
            rate_limit: 42,
        },
    }
}

fn backend(endpoint: &str) -> BackendDescriptor {
    BackendDescriptor {
        id: "mail".to_string(),
        audience: "https://mail.internal".to_string(),
        token_exchange_endpoint: Some(endpoint.to_string()),
        token_exchange_scope: Some("backends:mail-svc tools:mail_read".to_string()),
    }
}

// (a) A real RFC 8693 round trip against the gateway's own /auth/token
// obtains a policy-scoped downstream token and injects it as the outbound
// `Authorization` header.
#[tokio::test]
async fn token_exchange_obtains_scoped_token_and_injects_authorization() {
    let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    let live = LiveServer::start(&key, vec![allow_all_policy()]).await;

    let strategy =
        TokenExchangeStrategy::with_http_client(Arc::clone(&key), 300, reqwest::Client::new());
    let backend = backend(&live.token_exchange_endpoint());
    let alice = identity("alice@corp.example");

    let cred = strategy
        .propagate(&alice, &backend)
        .await
        .expect("a real token-exchange round trip must succeed");

    let auth_header = cred
        .headers
        .iter()
        .find(|(k, _)| k == "Authorization")
        .map(|(_, v)| v.clone())
        .expect("Authorization header must be injected");
    let bearer = auth_header
        .strip_prefix("Bearer ")
        .expect("must be a Bearer credential");

    // The injected token is not a bare echo — it is the REAL opaque bearer
    // the key server minted and stored, scoped by the policy engine.
    let (_, temp) = live
        .key_server
        .validate_token(bearer)
        .await
        .expect("the injected token must validate against the live key server's store");
    assert_eq!(temp.scopes.backends, vec!["mail-svc"]);
    assert_eq!(temp.scopes.tools, vec!["mail_read"]);
    assert_eq!(temp.scopes.rate_limit, 42);
    assert_eq!(temp.identity.email, "alice@corp.example");

    live.kill();
}

// (b) A backend denied by policy (no matching rule -> the live handler
// returns a real HTTP 403) must fail closed, never falling back to a static
// credential.
#[tokio::test]
async fn token_exchange_policy_denial_fails_closed() {
    let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    // No policy rules at all: every identity is denied by the real handler.
    let live = LiveServer::start(&key, Vec::new()).await;

    let strategy =
        TokenExchangeStrategy::with_http_client(Arc::clone(&key), 300, reqwest::Client::new());
    let backend = backend(&live.token_exchange_endpoint());
    let outsider = identity("outsider@other.example");

    let err = strategy
        .propagate(&outsider, &backend)
        .await
        .expect_err("a real 403 from the token endpoint must refuse, not downgrade");
    assert!(
        matches!(
            err,
            crate::identity_propagation::PropagationError::Refuse(_)
        ),
        "got {err:?}"
    );

    live.kill();
}

// (b) An unconfigured backend (no token_exchange_endpoint) fails closed even
// while a real, healthy token-exchange server is reachable — proving the
// fail-closed check is a config gate, not a network-reachability check.
#[tokio::test]
async fn token_exchange_unconfigured_endpoint_fails_closed_even_with_live_server() {
    let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    let live = LiveServer::start(&key, vec![allow_all_policy()]).await;

    let strategy =
        TokenExchangeStrategy::with_http_client(Arc::clone(&key), 300, reqwest::Client::new());
    let mut unconfigured = backend(&live.token_exchange_endpoint());
    unconfigured.token_exchange_endpoint = None;
    let alice = identity("alice@corp.example");

    let err = strategy
        .propagate(&alice, &unconfigured)
        .await
        .expect_err("missing token_exchange_endpoint must refuse regardless of server health");
    assert!(
        matches!(
            err,
            crate::identity_propagation::PropagationError::Misconfigured(_)
        ),
        "got {err:?}"
    );

    live.kill();
}

// (c) A second call within the exchanged token's TTL is served from the
// in-memory cache with ZERO additional HTTP round trips — proven by killing
// the server after the first exchange and asserting the second call still
// succeeds, returning the identical cached bearer.
#[tokio::test]
async fn token_exchange_second_call_within_ttl_served_from_cache_no_network() {
    let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    let live = LiveServer::start(&key, vec![allow_all_policy()]).await;

    let strategy =
        TokenExchangeStrategy::with_http_client(Arc::clone(&key), 300, reqwest::Client::new());
    let backend = backend(&live.token_exchange_endpoint());
    let alice = identity("alice@corp.example");

    let first = strategy
        .propagate(&alice, &backend)
        .await
        .expect("first exchange must succeed");

    // Kill the server outright: any code path that still tries the network
    // for the second call will fail to connect and this test will fail.
    live.kill();

    let second = strategy
        .propagate(&alice, &backend)
        .await
        .expect("cache hit must not require the (now-dead) token server");

    assert_eq!(
        first.headers, second.headers,
        "cached call must return the identical bearer, not mint a fresh one"
    );
    assert_eq!(first.cache_binding, second.cache_binding);
}
