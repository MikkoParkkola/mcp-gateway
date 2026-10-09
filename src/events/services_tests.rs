// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;
use crate::config::{ApiKeyConfig, ApiKeyKind, Config, api_key_digest_spec};

fn key(
    name: &str,
    secret: &str,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(api_key_digest_spec(secret.as_bytes())),
        expires_at,
        name: name.to_owned(),
        rate_limit: 0,
        backends: vec!["x".to_owned()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: ApiKeyKind::Shared,
    }
}

fn services(keys: Vec<ApiKeyConfig>) -> Services {
    let mut config = Config::default();
    config.auth.api_keys = keys;
    Services {
        live: Arc::new(LiveConfig::new(config)),
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: None,
        provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: LiveCredentials::default(),
    }
}

fn presented(name: &str, secret: &str) -> ApiKeyRef {
    ApiKeyRef {
        name: name.to_owned(),
        principal: crate::gateway::auth::principal_of(secret),
    }
}

#[test]
fn the_receipt_is_signed_only_when_stamping_is_on() {
    let bare = services(Vec::new()).provenance("hooks", "webhook.c.r.received");
    assert_eq!(bare["receipt"]["subject_kind"], "event");
    assert!(bare.get("signature").is_none());
    let signer = crate::attestation::BnautAttestationSigner::new(b"k".to_vec(), "id")
        .with_audience("test-gateway");
    let stamped = Services {
        provenance: Some(Arc::new(signer)),
        ..services(Vec::new())
    }
    .provenance("hooks", "webhook.c.r.received");
    assert_eq!(stamped["receipt"]["backend_id"], "hooks");
    assert!(stamped["signature"].as_str().is_some_and(|s| !s.is_empty()));
}

#[test]
fn the_live_key_must_match_by_secret_be_unexpired_and_grant_the_backend() {
    let alice = presented("alice", "s1");
    assert!(services(vec![key("alice", "s1", None)]).admits(Some(&alice), "x"));
    assert!(
        !services(vec![key("alice", "s1", None)]).admits(Some(&alice), "y"),
        "backend not granted"
    );
    assert!(
        !services(vec![key("alice", "s2", None)]).admits(Some(&alice), "x"),
        "replaced under the same name"
    );
    let past = chrono::Utc::now() - crate::duration_bound::delta!(seconds, 1);
    assert!(
        !services(vec![key("alice", "s1", Some(past))]).admits(Some(&alice), "x"),
        "expired"
    );
    assert!(!services(Vec::new()).admits(Some(&alice), "x"), "removed");
    assert!(
        services(Vec::new()).admits(None, "x"),
        "no API key to re-read"
    );
}

#[tokio::test]
async fn a_subscription_stored_with_a_bare_key_name_is_refused() {
    let stored = serde_json::json!({
        "v": 1, "id": "s", "principal": "p", "api_key_name": "alice",
        "url": "https://h/x", "name": "e", "arguments": {}, "secret": "whsec_x",
        "previous_secret": null, "previous_until": null,
        "granted_at": "2026-10-01T00:00:00Z", "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null
    });
    let sub: Subscription = serde_json::from_value(stored).expect("loads");
    let live = services(vec![key("alice", "s1", None)]);
    assert!(!live.admits_subscription(&sub, Some("x")).await);
    let rewritten = serde_json::to_value(&sub).expect("serialises");
    assert!(
        rewritten.get("api_key_name").is_none(),
        "never written back"
    );
}

fn bound(
    kind: crate::security::audit::CredentialKind,
    binding: Option<LiveBinding>,
) -> Subscription {
    let mut sub: Subscription = serde_json::from_value(serde_json::json!({
        "v": 1, "id": "s", "principal": "p", "url": "https://h/x", "name": "e",
        "arguments": {}, "secret": "whsec_x", "previous_secret": null,
        "previous_until": null, "granted_at": "2026-10-01T00:00:00Z",
        "expires_at": null, "active": true, "failed_since": null,
        "last_delivery_at": null, "last_error": null
    }))
    .expect("subscription");
    sub.credential_kind = Some(kind);
    sub.credential_principal = Some(crate::gateway::auth::principal_of("old"));
    sub.binding = binding;
    sub
}

fn with(credentials: LiveCredentials) -> Services {
    Services {
        credentials,
        ..services(Vec::new())
    }
}

fn key_server(delegated: bool) -> Arc<crate::key_server::KeyServer> {
    key_server_with(delegated, "a", 3600)
}

fn key_server_with(
    delegated: bool,
    audience: &str,
    max_age: u64,
) -> Arc<crate::key_server::KeyServer> {
    let config = serde_json::from_value(serde_json::json!({
        "enabled": true,
        "delegated_bearer": delegated,
        "max_oidc_token_age_secs": max_age,
        "oidc": [{"issuer": "https://idp", "audiences": [audience]}],
        "policies": [{
            "match": {"issuer": "https://idp", "domain": "corp.example"},
            "scopes": {"backends": ["x"]}
        }]
    }))
    .expect("key server config");
    Arc::new(crate::key_server::KeyServer::new(config))
}

/// Design F9 (MIK-7769): the running static bearer must be the one the
/// subscription was made with.
#[tokio::test]
async fn a_static_bearer_subscription_needs_the_same_running_bearer() {
    use crate::security::audit::CredentialKind as Kind;
    let sub = bound(Kind::StaticBearer, Some(LiveBinding::StaticBearer));
    let same = with(LiveCredentials {
        bearer_principal: Some(crate::gateway::auth::principal_of("old")),
        ..LiveCredentials::default()
    });
    assert!(same.admits_subscription(&sub, Some("x")).await);
    let rotated = with(LiveCredentials {
        bearer_principal: Some(crate::gateway::auth::principal_of("new")),
        ..LiveCredentials::default()
    });
    assert!(
        !rotated.admits_subscription(&sub, Some("x")).await,
        "rotated bearer"
    );
    let mismatched = bound(Kind::KeyServerToken, Some(LiveBinding::StaticBearer));
    assert!(
        !same.admits_subscription(&mismatched, Some("x")).await,
        "a binding of another kind is refused"
    );
}

/// MIK-7889 (#2695): the static-bearer re-check compares the full SHA-256 of
/// the bearer, not only the 12-hex log fingerprint. A running bearer whose
/// fingerprint matches but whose digest differs is refused.
#[tokio::test]
async fn a_static_bearer_recheck_compares_the_full_digest() {
    use crate::security::audit::CredentialKind as Kind;
    let digest = |t: &str| crate::hashing::sha256_hex(t.as_bytes());
    let sub = bound(
        Kind::StaticBearer,
        Some(LiveBinding::StaticBearerSha256 {
            bearer_sha256: digest("old"),
        }),
    );
    let live = |token: &str, fingerprint_of: &str| {
        with(LiveCredentials {
            bearer_principal: Some(crate::gateway::auth::principal_of(fingerprint_of)),
            bearer_sha256: Some(digest(token)),
            ..LiveCredentials::default()
        })
    };
    assert!(
        live("old", "old")
            .admits_subscription(&sub, Some("x"))
            .await
    );
    assert!(
        !live("other", "old")
            .admits_subscription(&sub, Some("x"))
            .await,
        "same 12-hex fingerprint, different bearer"
    );
    let none = with(LiveCredentials {
        bearer_principal: Some(crate::gateway::auth::principal_of("old")),
        ..LiveCredentials::default()
    });
    assert!(
        !none.admits_subscription(&sub, Some("x")).await,
        "no running digest, no admission"
    );
}

/// MIK-7889: the running bearer yields both the fingerprint and the digest,
/// and none without a bearer.
#[test]
fn the_running_static_bearer_yields_a_fingerprint_and_a_full_digest() {
    let (principal, digest) = LiveCredentials::static_bearer(Some("tok"));
    assert_eq!(principal, Some(crate::gateway::auth::principal_of("tok")));
    assert_eq!(digest, Some(crate::hashing::sha256_hex(b"tok")));
    assert_eq!(digest.unwrap().len(), 64);
    assert_eq!(LiveCredentials::static_bearer(None), (None, None));
}

/// Design F9 (MIK-7769): key-server tokens live until revoked; delegated
/// bearers while the live policy grants the backend; a bound kind
/// without its binding is refused.
#[tokio::test]
async fn key_server_credentials_are_rechecked_where_they_were_issued() {
    use crate::security::audit::CredentialKind as Kind;
    let ks = key_server(false);
    let identity = crate::key_server::oidc::VerifiedIdentity {
        subject: "u".into(),
        email: "u@corp.example".into(),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp".into(),
    };
    let now = u64::try_from(chrono::Utc::now().timestamp()).expect("now");
    ks.store
        .insert(crate::key_server::TemporaryToken {
            jti: "j1".into(),
            token: "mcpgw_t".into(),
            identity: identity.clone(),
            scopes: crate::key_server::store::TokenScopes {
                backends: vec!["x".into()],
                tools: Vec::new(),
                rate_limit: 0,
            },
            iat: now,
            exp: now + 600,
            client_ip: None,
        })
        .await;
    let live = with(LiveCredentials {
        key_server: Some(Arc::clone(&ks)),
        ..LiveCredentials::default()
    });
    let token = bound(
        Kind::KeyServerToken,
        Some(LiveBinding::KeyServerToken { jti: "j1".into() }),
    );
    assert!(live.admits_subscription(&token, Some("x")).await);
    ks.store.revoke_by_jti("j1").await;
    assert!(
        !live.admits_subscription(&token, Some("x")).await,
        "revoked token"
    );
    assert!(
        !with(LiveCredentials::default())
            .admits_subscription(&token, Some("x"))
            .await,
        "no key server, nothing to vouch for the token"
    );

    let unbound = bound(Kind::KeyServerToken, None);
    assert!(!live.admits_subscription(&unbound, Some("x")).await);
}

/// Design F9 (MIK-7769): a delegated bearer is re-checked against the
/// running key server: its policy grant, the delegated-bearer switch, the
/// verifying provider's configuration and the max token age.
#[tokio::test]
async fn a_delegated_bearer_is_rechecked_against_the_running_key_server() {
    use crate::security::audit::CredentialKind as Kind;
    let ks = key_server(true);
    let now = u64::try_from(chrono::Utc::now().timestamp()).expect("now");
    let oidc = |issued_at| {
        bound(
            Kind::OidcBearer,
            Some(LiveBinding::OidcBearer {
                issuer: "https://idp".into(),
                subject: "u".into(),
                email: "u@corp.example".into(),
                groups: Vec::new(),
                issued_at: Some(issued_at),
                provider_sha256: crate::gateway::auth::live::provider_fingerprint(
                    &ks,
                    "https://idp",
                ),
            }),
        )
    };
    let running = |ks| {
        with(LiveCredentials {
            key_server: Some(ks),
            ..LiveCredentials::default()
        })
    };
    let fresh = oidc(now);
    assert!(
        running(key_server(true))
            .admits_subscription(&fresh, Some("x"))
            .await
    );
    assert!(
        !running(key_server(true))
            .admits_subscription(&fresh, Some("y"))
            .await,
        "no grant"
    );
    assert!(
        !running(key_server(false))
            .admits_subscription(&fresh, Some("x"))
            .await,
        "delegated bearers switched off"
    );
    assert!(
        !running(key_server_with(true, "b", 3600))
            .admits_subscription(&fresh, Some("x"))
            .await,
        "the provider now expects another audience"
    );
    assert!(
        !running(key_server_with(true, "a", 60))
            .admits_subscription(&oidc(now - 600), Some("x"))
            .await,
        "older than the running max age"
    );
}

/// Design F9 (MIK-7769): a dashboard session's subscription stops once the
/// session is logged out.
#[tokio::test]
async fn a_dashboard_session_subscription_ends_at_logout() {
    use crate::security::audit::CredentialKind as Kind;
    let dashboard = Arc::new(crate::gateway::auth::DashboardBootstrap::new());
    let handle = dashboard.issue_session();
    let session = bound(
        Kind::DashboardSession,
        Some(LiveBinding::DashboardSession {
            session_sha256: crate::hashing::sha256_hex(handle.as_bytes()),
        }),
    );
    let open = with(LiveCredentials {
        dashboard: Some(Arc::clone(&dashboard)),
        ..LiveCredentials::default()
    });
    assert!(open.admits_subscription(&session, Some("x")).await);
    let limits = crate::gateway::auth::SessionLimits::default();
    assert!(dashboard.revoke(&handle, crate::gateway::auth::Now::read(), &limits));
    assert!(
        !open.admits_subscription(&session, Some("x")).await,
        "logged out"
    );
}

/// MIK-7903: an event charge settles its reservation with its spend, so a
/// check that runs inside the settle sees the charge once.
#[cfg(feature = "cost-governance")]
#[test]
fn an_event_charge_settles_its_reservation_with_its_spend() {
    use crate::cost_accounting::config::CostGovernanceConfig;
    use crate::cost_accounting::enforcer::BudgetEnforcer;
    use crate::cost_accounting::registry::CostRegistry;

    // GIVEN: room for two charges of 1.0 on `dev`
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..CostGovernanceConfig::default()
    };
    cfg.budgets.per_key.insert("dev".to_owned(), 2.5);
    let registry = Arc::new(CostRegistry::new(&cfg));
    let enforcer = Arc::new(BudgetEnforcer::new(cfg, Arc::clone(&registry)));
    let mut services = services(Vec::new());
    services.budget = Some((Arc::clone(&enforcer), registry));
    let competing = enforcer.check_inside_next_settle("events:ev", Some("dev"));
    // WHEN: one charge settles, with a check made inside its settle
    assert!(services.charge("ev", Some("dev"), 1.0));
    // THEN: the charge counts once, so the second still fits
    assert!(
        competing.admitted(),
        "the charge was counted twice inside its settle"
    );
}
