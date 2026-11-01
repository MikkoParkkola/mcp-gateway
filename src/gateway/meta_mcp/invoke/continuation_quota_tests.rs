// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8659: pins `QuotaSource::KeyName` for an anonymous direct caller;
//! whether a continuation is minted depends on the binding (bound: minted; unbound: refused).

use super::{direct_quota_key, direct_source, mint_continuation, redeem_retry};
use crate::protocol::continuation::{QuotaKey, QuotaSource};

/// MIK-8659 T4 direct-anonymous (RED): the red probe. Pins the unified
/// key-name quota for an anonymous direct caller.
#[test]
fn an_anonymous_direct_caller_gets_the_meta_routes_key_name_quota() {
    let client = crate::gateway::auth::anonymous_client();
    let key = direct_quota_key((None, (None, None), Some(&client)));
    assert_eq!(key, Some(QuotaKey::new(QuotaSource::KeyName("anonymous"))));
}

/// Build a caller context from a client, mirroring dispatch (api key name,
/// credential principal, authentication, credential kind).
fn context_for(
    client: &crate::gateway::auth::AuthenticatedClient,
) -> crate::gateway::meta_mcp::MetaMcpCallerContext<'_> {
    crate::gateway::meta_mcp::MetaMcpCallerContext {
        api_key_name: Some(client.name.as_str()),
        credential_principal: Some(client.principal.storage_form()),
        record_principal: crate::gateway::record_principal::RecordPrincipal::none(),
        authentication: crate::gateway::meta_mcp::Authentication::of(Some(client)),
        credential_kind: crate::security::audit::CredentialKind::of(Some(client)),
        ..crate::gateway::meta_mcp::anonymous_caller()
    }
}

/// MIK-8659 T1a (GREEN): the gateway mints agree on the context F0 readers
/// from this module too: cost key and grant key equal the shared oracle.
#[test]
fn t1a_context_readers_agree_over_gateway_mints() {
    for (label, client) in crate::gateway::auth::mints() {
        if label.starts_with("bad_") {
            continue;
        }
        let expected = crate::gateway::auth::expected_api_key(&client);
        let ctx = context_for(&client);
        assert_eq!(ctx.cost_key(), expected, "{label}: cost_key");
        assert_eq!(ctx.scope().grant_key, expected, "{label}: grant_key");
    }
}

/// MIK-8659 T1a key-server token (GREEN): a real exchanged token is no API
/// key on any F0 reader.
#[tokio::test]
async fn t1a_key_server_token_has_no_api_key_identity() {
    let ks = crate::key_server::KeyServer::new(crate::config::KeyServerConfig::default());
    ks.store
        .insert(crate::key_server::TemporaryToken {
            jti: "jti-mik-8659".to_owned(),
            token: "mcpgw_mik_8659_token".to_owned(),
            identity: crate::key_server::oidc::VerifiedIdentity {
                subject: "alice".to_owned(),
                email: "alice@example.com".to_owned(),
                name: None,
                groups: vec![],
                issuer: "https://issuer.invalid".to_owned(),
            },
            scopes: crate::key_server::store::TokenScopes::default(),
            iat: 0,
            exp: u64::MAX,
            client_ip: None,
        })
        .await;
    let (client, _) = ks
        .validate_token("mcpgw_mik_8659_token")
        .await
        .expect("exchanged token validates");
    assert_eq!(
        crate::gateway::auth::expected_api_key(&client),
        None,
        "oracle pins None for a key-server token"
    );
    assert_eq!(client.api_key_identity(), None);
    let ctx = context_for(&client);
    assert_eq!(ctx.cost_key(), None);
    assert_eq!(ctx.scope().grant_key, None);
}

/// MIK-8659 T1a OIDC bearer (GREEN): a real delegated bearer is no API key
/// on any F0 reader.
#[tokio::test]
async fn t1a_oidc_bearer_has_no_api_key_identity() {
    use crate::key_server::oidc_test_harness::{Harness, ISS_A, config_yaml};
    let yaml = config_yaml(
        "[]",
        "policies:\n  - match: { issuer: \"https://idp-a.example\" }\n    scopes: { backends: [\"*\"], tools: [\"*\"], rate_limit: 0 }\n",
    );
    let harness = Harness::start(&yaml).await;
    let token = harness.mint(ISS_A, "alice", &serde_json::json!({}));
    let (client, _) = harness
        .ks
        .verify_bearer_identity(&token)
        .await
        .expect("delegated bearer verifies");
    assert_eq!(
        crate::gateway::auth::expected_api_key(&client),
        None,
        "oracle pins None for an OIDC bearer"
    );
    assert_eq!(client.api_key_identity(), None);
    let ctx = context_for(&client);
    assert_eq!(ctx.cost_key(), None);
    assert_eq!(ctx.scope().grant_key, None);
}

/// MIK-8659 T4 direct-public (RED): a public caller is charged to its own
/// key-name quota on the direct route, not refused and not pooled under
/// "anonymous". Today the direct route has no key-name fallback, so this is
/// `None` and fails.
#[test]
fn t4_direct_public_gets_its_own_key_name_quota() {
    let (_, client) = crate::gateway::auth::mints()
        .into_iter()
        .find(|(label, _)| *label == "public")
        .expect("public mint is labelled");
    let key = direct_quota_key((None, (None, None), Some(&client)));
    assert_eq!(key, Some(QuotaKey::new(QuotaSource::KeyName("public"))));
}

/// MIK-8659 T4 meta-public (GREEN): the meta route already charges a public
/// caller to `KeyName("public")`. Control for the direct row above.
#[test]
fn t4_meta_public_gets_its_own_key_name_quota() {
    let (_, client) = crate::gateway::auth::mints()
        .into_iter()
        .find(|(label, _)| *label == "public")
        .expect("public mint is labelled");
    let ctx = context_for(&client);
    assert_eq!(
        ctx.quota_key(),
        Some(QuotaKey::new(QuotaSource::KeyName("public")))
    );
}

/// MIK-8659 T4 (GREEN): an API key is charged to its credential principal on
/// both routes, never to a key name.
#[test]
fn t4_api_key_gives_credential_quota_on_both_routes() {
    let (_, client) = crate::gateway::auth::mints()
        .into_iter()
        .find(|(label, _)| *label == "api_key")
        .expect("api_key mint is labelled");
    let expected = Some(QuotaKey::new(QuotaSource::Credential(
        client.principal.storage_form(),
    )));
    let ctx = context_for(&client);
    assert_eq!(ctx.quota_key(), expected, "meta charges the credential");
    let direct = direct_quota_key((None, (None, None), Some(&client)));
    assert_eq!(direct, expected, "direct charges the credential");
}

/// MIK-8659 T4 (GREEN): an OIDC caller is charged to its verified identity
/// when one is passed, on both routes. Without the identity it falls through
/// to the credential; wiring it as a credential when an identity is present
/// fails here.
#[test]
fn t4_oidc_gives_identity_quota_when_an_identity_is_passed() {
    let identity = crate::key_server::oidc::VerifiedIdentity {
        subject: "alice".to_owned(),
        email: String::new(),
        name: None,
        groups: vec![],
        issuer: "https://idp.example".to_owned(),
    };
    let client = crate::gateway::auth::AuthenticatedClient {
        name: "alice".to_owned(),
        rate_limit: 0,
        backends: vec!["*".to_owned()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        // MIK-6704.IDENT.1a: a synthetic fixture, not an authorization path.
        principal: crate::gateway::record_principal::InternalPrincipal::new(
            "oidc-principal".to_owned(),
        ),
        quota_principal: None,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::OidcBearer,
    };
    let expected = Some(QuotaKey::new(QuotaSource::Identity(&identity)));
    let ctx = crate::gateway::meta_mcp::MetaMcpCallerContext {
        api_key_name: Some(client.name.as_str()),
        credential_principal: Some(client.principal.storage_form()),
        record_principal: crate::gateway::record_principal::RecordPrincipal::none(),
        authentication: crate::gateway::meta_mcp::Authentication::of(Some(&client)),
        credential_kind: crate::security::audit::CredentialKind::of(Some(&client)),
        verified_identity: Some(&identity),
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    assert_eq!(ctx.quota_key(), expected, "meta charges the identity");
    let direct = direct_quota_key((Some(&identity), (None, None), Some(&client)));
    assert_eq!(direct, expected, "direct charges the identity");
}

/// MIK-8659 T4 precedence (GREEN): identity beats subject beats credential
/// beats key name; an empty principal falls through; an empty name gives
/// `None`; stdio beats everything on the meta route.
#[test]
fn t4_quota_precedence_and_fallthrough() {
    let identity = crate::key_server::oidc::VerifiedIdentity {
        subject: "alice".to_owned(),
        email: String::new(),
        name: None,
        groups: vec![],
        issuer: "https://idp.example".to_owned(),
    };
    let subject = crate::identity_grants::GrantSubject::new("proxy", "bob", None);
    let nonce = crate::gateway::StdioNonce::leaked_for_test();
    // Identity + subject + principal + name -> identity.
    let full = crate::gateway::meta_mcp::MetaMcpCallerContext {
        api_key_name: Some("k"),
        credential_principal: Some("p"),
        record_principal: crate::gateway::record_principal::RecordPrincipal::none(),
        authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
        verified_identity: Some(&identity),
        grant_subject: Some(subject.clone()),
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    assert_eq!(
        full.quota_key(),
        Some(QuotaKey::new(QuotaSource::Identity(&identity))),
        "identity wins"
    );
    // Subject + principal + name -> subject.
    let no_identity = crate::gateway::meta_mcp::MetaMcpCallerContext {
        api_key_name: Some("k"),
        credential_principal: Some("p"),
        record_principal: crate::gateway::record_principal::RecordPrincipal::none(),
        authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
        verified_identity: None,
        grant_subject: Some(subject.clone()),
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    assert_eq!(
        no_identity.quota_key(),
        Some(QuotaKey::new(QuotaSource::Subject(&subject))),
        "subject wins without identity"
    );
    // Empty principal falls through to the name.
    let empty_principal = crate::gateway::meta_mcp::MetaMcpCallerContext {
        api_key_name: Some("k"),
        credential_principal: Some(""),
        record_principal: crate::gateway::record_principal::RecordPrincipal::none(),
        authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
        verified_identity: None,
        grant_subject: None,
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    assert_eq!(
        empty_principal.quota_key(),
        Some(QuotaKey::new(QuotaSource::KeyName("k"))),
        "empty principal falls through to the name"
    );
    // Empty name -> None.
    let empty_name = crate::gateway::meta_mcp::MetaMcpCallerContext {
        api_key_name: Some(""),
        credential_principal: None,
        record_principal: crate::gateway::record_principal::RecordPrincipal::none(),
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    assert_eq!(empty_name.quota_key(), None, "empty name gives None");
    // Stdio beats everything on meta.
    let stdio = crate::gateway::meta_mcp::MetaMcpCallerContext {
        api_key_name: Some("k"),
        credential_principal: Some("p"),
        record_principal: crate::gateway::record_principal::RecordPrincipal::none(),
        authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
        verified_identity: Some(&identity),
        grant_subject: Some(subject.clone()),
        stdio_nonce: Some(nonce),
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    assert_eq!(
        stdio.quota_key(),
        Some(QuotaKey::new(QuotaSource::Stdio(nonce.bytes()))),
        "stdio wins on meta"
    );
    // Stdio is meta only: the direct route takes no stdio input, so its
    // absence there is stated, not asserted on a value.
}

/// MIK-8659 T3 (GREEN): `credential_owner` goldens. Literals independent of
/// the constant: a bare principal gains the prefix, an already-prefixed one
/// is unchanged.
#[test]
fn t3_credential_owner_goldens() {
    let bare = crate::gateway::meta_mcp::MetaMcpCallerContext {
        authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
        credential_principal: Some("ab12"),
        record_principal: crate::gateway::record_principal::RecordPrincipal::none(),
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    assert_eq!(
        crate::gateway::meta_mcp::support::credential_owner(&bare),
        Some("credential:ab12".to_owned())
    );
    let prefixed = crate::gateway::meta_mcp::MetaMcpCallerContext {
        authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
        credential_principal: Some("credential:ab12"),
        record_principal: crate::gateway::record_principal::RecordPrincipal::none(),
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    assert_eq!(
        crate::gateway::meta_mcp::support::credential_owner(&prefixed),
        Some("credential:ab12".to_owned())
    );
}

/// MIK-8659 T3 (GREEN): `caller_cache_principal` golden. An authenticated
/// `ab12` digest keys as `cred:4:ab12`.
#[test]
fn t3_caller_cache_principal_golden() {
    assert_eq!(
        crate::gateway::meta_mcp::support::caller_cache_principal(
            None,
            None,
            None,
            Some("ab12"),
            crate::gateway::meta_mcp::Authentication::Authenticated,
        ),
        crate::gateway::meta_mcp::support::CachePrincipal::Caller("cred:4:ab12".to_owned()),
    );
}

/// MIK-8659 T2 (GREEN): authenticated mints carry a principal: owner, cache
/// key and both quota routes see it.
#[test]
fn t2_authenticated_mints_carry_a_principal() {
    for (label, client) in crate::gateway::auth::mints() {
        if !client.authenticated || client.principal.is_empty() {
            continue;
        }
        let ctx = context_for(&client);
        assert!(
            crate::gateway::meta_mcp::support::credential_owner(&ctx).is_some(),
            "{label}: owner"
        );
        assert_eq!(
            ctx.quota_key(),
            Some(QuotaKey::new(QuotaSource::Credential(
                client.principal.storage_form()
            ))),
            "{label}: meta quota is Credential"
        );
        assert_eq!(
            direct_quota_key((None, (None, None), Some(&client))),
            Some(QuotaKey::new(QuotaSource::Credential(
                client.principal.storage_form()
            ))),
            "{label}: direct quota is Credential"
        );
    }
}

/// MIK-8659 T2 (GREEN): `{authenticated: false, principal: "p"}` gives no
/// principal, no owner and no credential quota on either route.
#[test]
fn t2_unauthenticated_principal_gives_none() {
    let (_, client) = crate::gateway::auth::mints()
        .into_iter()
        .find(|(label, _)| *label == "bad_unauthenticated_api_key_T1b")
        .expect("T1b bad pair is labelled");
    let ctx = context_for(&client);
    assert_eq!(
        crate::gateway::meta_mcp::support::credential_owner(&ctx),
        None,
        "no owner"
    );
    assert_eq!(
        ctx.quota_key(),
        Some(QuotaKey::new(QuotaSource::KeyName("k"))),
        "meta falls through to the key name, not Credential"
    );
    assert_ne!(
        direct_quota_key((None, (None, None), Some(&client))),
        Some(QuotaKey::new(QuotaSource::Credential("p"))),
        "direct never charges an unauthenticated principal as Credential"
    );
}

/// MIK-8659 T2 (GREEN): `{authenticated: true, principal: ""}` gives no
/// principal and no credential quota, and the cache principal is
/// `Unresolved`, never pooled with anonymous.
#[test]
fn t2_empty_principal_gives_none_and_unresolved() {
    let (_, client) = crate::gateway::auth::mints()
        .into_iter()
        .find(|(label, _)| *label == "bad_empty_principal_T1e")
        .expect("T1e bad pair is labelled");
    let ctx = context_for(&client);
    assert_eq!(
        crate::gateway::meta_mcp::support::credential_owner(&ctx),
        None,
        "no owner for an empty principal"
    );
    assert_eq!(
        crate::gateway::meta_mcp::support::caller_cache_principal(
            None,
            None,
            None,
            Some(""),
            crate::gateway::meta_mcp::Authentication::Authenticated,
        ),
        crate::gateway::meta_mcp::support::CachePrincipal::Unresolved,
        "empty stays Unresolved, never Anonymous"
    );
    assert_ne!(
        direct_quota_key((None, (None, None), Some(&client))),
        Some(QuotaKey::new(QuotaSource::Credential(""))),
        "direct never charges an empty principal as Credential"
    );
}

/// MIK-8659 T2 auth-off worker (GREEN): `Anonymous` with
/// `AUTH_DISABLED_TASK_OWNER` and no stdio, identity or subject gives no
/// principal, no owner and no `Credential` quota.
#[test]
fn t2_auth_disabled_task_worker_has_no_credential() {
    // The value of `tasks::owner::AUTH_DISABLED_TASK_OWNER`; the row pins
    // that a non-empty principal without authentication still gives nothing.
    let ctx = crate::gateway::meta_mcp::MetaMcpCallerContext {
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        credential_principal: Some("local:auth-disabled:tasks:v1"),
        record_principal: crate::gateway::record_principal::RecordPrincipal::none(),
        credential_kind: crate::security::audit::CredentialKind::None,
        api_key_name: None,
        verified_identity: None,
        grant_subject: None,
        stdio_nonce: None,
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    assert_eq!(
        crate::gateway::meta_mcp::support::credential_owner(&ctx),
        None,
        "no owner without authentication"
    );
    assert_eq!(ctx.quota_key(), None, "no quota arm fires");
}

/// MIK-8659 T1d (GREEN): a context with no credential principal yields no
/// events-hook `ApiKeyRef`, so a backend event stays visible through the
/// hook's own search path (no live scope to re-read).
#[tokio::test]
async fn t1d_missing_principal_yields_no_api_key_ref() {
    let found = events_search_visible("k", None).await;
    assert!(
        found,
        "T1d: None principal means no ApiKeyRef, so the backend event is visible"
    );
}

/// MIK-8659 T1e (RED): a context with an empty credential principal must
/// yield no `ApiKeyRef` either. Today the hook builds one with the empty
/// string, the live check refuses it, and the event disappears.
#[tokio::test]
async fn t1e_empty_principal_yields_no_api_key_ref() {
    let found = events_search_visible("k", Some("")).await;
    assert!(
        found,
        "T1e: empty principal must mean no ApiKeyRef, so the backend event is visible"
    );
}

/// MIK-8659 T1d/T1e control (GREEN): an authenticated API-key caller WITH a
/// principal does get an `ApiKeyRef`. The harness's live config has no key
/// named `k`, so the hook's live re-check refuses it and the backend event is
/// hidden. Deleting the hook's `ApiKeyRef` construction makes this red.
#[tokio::test]
async fn t1de_control_principal_yields_an_api_key_ref() {
    let found = events_search_visible("k", Some("p")).await;
    assert!(
        !found,
        "control: a non-empty principal builds an ApiKeyRef, so the live re-check hides the event"
    );
}

/// Seed one backend event on `alpha`, install a live config with no API key
/// `name`, and report whether the hook's search path shows it to a caller
/// `{Authenticated, ApiKey, name, principal}`.
async fn events_search_visible(name: &str, principal: Option<&str>) -> bool {
    let dir = tempfile::TempDir::new().expect("temp store");
    let hub = crate::events::EventsHub::open(&crate::config::EventsConfig::default(), dir.path())
        .expect("hub");
    hub.install_backend_source(std::sync::Arc::new(|| vec!["alpha".to_owned()]));
    let live = std::sync::Arc::new(crate::config_reload::LiveConfig::new(
        crate::config::Config::default(),
    ));
    let services = crate::events::Services {
        live,
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: None,
        provenance: None,
        public_provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: crate::events::LiveCredentials::default(),
        record_key: Some(crate::gateway::record_principal::test_key_arc()),
    };
    hub.start(services);
    let meta = crate::gateway::meta_mcp::MetaMcp::new(std::sync::Arc::new(
        crate::backend::BackendRegistry::new(),
    ));
    meta.set_events(hub);
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
        api_key_name: Some(name),
        credential_principal: principal,
        record_principal: crate::gateway::record_principal::RecordPrincipal::none(),
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    let matches = meta.event_search_matches("alpha", 10, &caller, None);
    matches.iter().any(|value| {
        value
            .get("name")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|name| name.contains("alpha"))
    })
}

#[path = "continuation_quota_t5_tests.rs"]
mod t5;
