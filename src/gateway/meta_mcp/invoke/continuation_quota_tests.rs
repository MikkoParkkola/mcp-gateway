// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8659: pins `QuotaSource::KeyName` for an anonymous direct caller;
//! whether a continuation is minted depends on the binding (bound: minted; unbound: refused).

use super::direct_quota_key;
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
        credential_principal: Some(client.principal.as_str()),
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
        client.principal.as_str(),
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
        principal: "oidc-principal".to_owned(),
        quota_principal: None,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::OidcBearer,
    };
    let expected = Some(QuotaKey::new(QuotaSource::Identity(&identity)));
    let ctx = crate::gateway::meta_mcp::MetaMcpCallerContext {
        api_key_name: Some(client.name.as_str()),
        credential_principal: Some(client.principal.as_str()),
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
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    assert_eq!(empty_name.quota_key(), None, "empty name gives None");
    // Stdio beats everything on meta.
    let stdio = crate::gateway::meta_mcp::MetaMcpCallerContext {
        api_key_name: Some("k"),
        credential_principal: Some("p"),
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
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    assert_eq!(
        crate::gateway::meta_mcp::support::credential_owner(&bare),
        Some("credential:ab12".to_owned())
    );
    let prefixed = crate::gateway::meta_mcp::MetaMcpCallerContext {
        authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
        credential_principal: Some("credential:ab12"),
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
                client.principal.as_str()
            ))),
            "{label}: meta quota is Credential"
        );
        assert_eq!(
            direct_quota_key((None, (None, None), Some(&client))),
            Some(QuotaKey::new(QuotaSource::Credential(
                client.principal.as_str()
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
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: crate::events::LiveCredentials::default(),
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

/// MIK-8659 T5 meta-bound (GREEN): a bound anonymous caller mints on meta at
/// the key-name quota.
#[tokio::test]
async fn t5_bound_anonymous_mints_on_meta() {
    let state = std::sync::Arc::new(crate::protocol::continuation::ContinuationState::new());
    let client = crate::gateway::auth::anonymous_client();
    let ctx = context_for(&client);
    assert_eq!(
        ctx.quota_key(),
        Some(QuotaKey::new(QuotaSource::KeyName("anonymous"))),
        "meta charges the key-name quota"
    );
    let quota = ctx.quota_key().expect("meta has a quota key");
    let source = ctx.principal_source(Some("binding-a"));
    let arguments = serde_json::json!({});
    let minted = super::mint_continuation(
        &state,
        source,
        &quota,
        ("fixture", None),
        "tool",
        &arguments,
        None,
    )
    .await;
    assert!(minted.is_some(), "bound anonymous mints on meta");
}

/// MIK-8659 T5 direct-bound quota (RED): a bound anonymous caller is charged
/// to the shared key-name quota on direct too. Today the direct route has no
/// fallback, so the quota is `None` and the mint never starts.
#[test]
fn t5_bound_anonymous_gets_key_name_quota_on_direct() {
    let client = crate::gateway::auth::anonymous_client();
    let key = direct_quota_key((None, (Some("binding-a"), None), Some(&client)));
    assert_eq!(
        key,
        Some(QuotaKey::new(QuotaSource::KeyName("anonymous"))),
        "direct charges the shared key-name quota"
    );
}

/// MIK-8659 T5 unbound (GREEN): an unbound anonymous caller is refused on
/// both routes: no fingerprint, so no mint.
#[tokio::test]
async fn t5_unbound_anonymous_is_refused_on_both_routes() {
    let state = std::sync::Arc::new(crate::protocol::continuation::ContinuationState::new());
    let client = crate::gateway::auth::anonymous_client();
    // Meta: quota exists, but the source has no fingerprint.
    let ctx = context_for(&client);
    let quota = ctx
        .quota_key()
        .expect("meta still charges the key-name quota");
    let source = ctx.principal_source(None);
    let arguments = serde_json::json!({});
    let minted = super::mint_continuation(
        &state,
        source,
        &quota,
        ("fixture", None),
        "tool",
        &arguments,
        None,
    )
    .await;
    assert!(minted.is_none(), "meta refuses the unbound caller");
    // Direct: quota exists, but the source has no fingerprint.
    let unbound = (None, (None, None), Some(&client));
    assert_eq!(
        direct_quota_key(unbound),
        Some(QuotaKey::new(QuotaSource::KeyName("anonymous"))),
        "direct charges the key-name quota"
    );
    let direct_minted = super::mint_continuation(
        &state,
        super::direct_source(unbound),
        &quota,
        ("fixture", None),
        "tool",
        &arguments,
        None,
    )
    .await;
    assert!(direct_minted.is_none(), "direct refuses the unbound caller");
}

/// MIK-8659 T5 wrong-binding-first (GREEN on meta): the wrong binding is
/// refused without consuming the round, then the rightful binding still
/// redeems. Proves the refusal is the binding check, not replay protection.
#[tokio::test]
async fn t5_wrong_binding_first_then_rightful_redeems_on_meta() {
    let state = std::sync::Arc::new(crate::protocol::continuation::ContinuationState::new());
    let quota = QuotaKey::new(QuotaSource::KeyName("anonymous"));
    let arguments = serde_json::json!({});
    let (envelope, _) = super::mint_continuation(
        &state,
        crate::protocol::mrtr::PrincipalSource::Key("idp:9:binding-a".to_owned()),
        &quota,
        ("fixture", None),
        "tool",
        &arguments,
        None,
    )
    .await
    .expect("bound anonymous mints");
    let retry = crate::protocol::mrtr::RetryFields {
        request_state: Some(envelope),
        ..Default::default()
    };
    let wrong = super::redeem_retry(
        &state,
        (
            crate::protocol::mrtr::PrincipalSource::Key("idp:9:binding-b".to_owned()),
            &retry,
        ),
        ("fixture", None),
        "tool",
        &arguments,
    )
    .await;
    assert!(
        wrong.is_err(),
        "wrong binding is refused, consuming nothing: {wrong:?}"
    );
    let right = super::redeem_retry(
        &state,
        (
            crate::protocol::mrtr::PrincipalSource::Key("idp:9:binding-a".to_owned()),
            &retry,
        ),
        ("fixture", None),
        "tool",
        &arguments,
    )
    .await;
    assert!(right.is_ok(), "rightful binding still redeems: {right:?}");
}

/// MIK-8659 T5 wrong-binding-first on direct (RED): the direct route charges a bound anonymous
/// caller to the key-name quota and binds it to its passthrough binding; a different binding is
/// refused without consuming the round, and the rightful one still redeems. Today
/// `direct_quota_key` gives None, so the mint never starts.
#[tokio::test]
async fn t5_wrong_binding_first_then_rightful_redeems_on_direct() {
    let state = std::sync::Arc::new(crate::protocol::continuation::ContinuationState::new());
    let client = crate::gateway::auth::anonymous_client();
    let a = (None, (Some("binding-a"), None), Some(&client));
    let b = (None, (Some("binding-b"), None), Some(&client));
    let quota = direct_quota_key(a).expect("direct charges a bound anonymous caller");
    let arguments = serde_json::json!({});
    let (envelope, _) = super::mint_continuation(
        &state,
        super::direct_source(a),
        &quota,
        ("fixture", None),
        "tool",
        &arguments,
        None,
    )
    .await
    .expect("bound anonymous mints");
    let retry = crate::protocol::mrtr::RetryFields {
        request_state: Some(envelope),
        ..Default::default()
    };
    let wrong = super::redeem_retry(
        &state,
        (super::direct_source(b), &retry),
        ("fixture", None),
        "tool",
        &arguments,
    )
    .await;
    assert!(
        wrong.is_err(),
        "wrong binding is refused, consuming nothing: {wrong:?}"
    );
    let right = super::redeem_retry(
        &state,
        (super::direct_source(a), &retry),
        ("fixture", None),
        "tool",
        &arguments,
    )
    .await;
    assert!(right.is_ok(), "rightful binding still redeems: {right:?}");
}

/// MIK-8659 T5 shared cap (RED): one `ContinuationState` serves both routes;
/// different bindings filling the shared anonymous key-name cap refuse the
/// next mint. Today the direct leg cannot even reach the cap (no quota key),
/// so the shared fill fails.
#[tokio::test]
async fn t5_shared_anonymous_cap_spans_both_routes() {
    let slots = crate::protocol::continuation::PRINCIPAL_SLOTS;
    let state = std::sync::Arc::new(crate::protocol::continuation::ContinuationState::new());
    let quota = QuotaKey::new(QuotaSource::KeyName("anonymous"));
    let arguments = serde_json::json!({});
    let client = crate::gateway::auth::anonymous_client();
    let half = slots / 2;
    for i in 0..half {
        let binding = format!("binding-{i}");
        let key = format!("idp:{}:{binding}", binding.len());
        let minted = super::mint_continuation(
            &state,
            crate::protocol::mrtr::PrincipalSource::Key(key),
            &quota,
            ("fixture", None),
            "tool",
            &arguments,
            None,
        )
        .await;
        assert!(minted.is_some(), "meta fill {i} mints");
    }
    let direct_bindings: Vec<String> = (half..slots)
        .map(|i| format!("cap-direct-{i:03}"))
        .collect();
    for (i, binding) in direct_bindings.iter().enumerate() {
        let caller = (None, (Some(binding.as_str()), None), Some(&client));
        let direct_quota = direct_quota_key(caller).expect("direct charges a bound caller");
        let minted = super::mint_continuation(
            &state,
            super::direct_source(caller),
            &direct_quota,
            ("fixture", None),
            "tool",
            &arguments,
            None,
        )
        .await;
        assert!(minted.is_some(), "direct fill {i} mints");
    }
    let overflow = super::mint_continuation(
        &state,
        crate::protocol::mrtr::PrincipalSource::Key("idp:16:binding-overflow".to_owned()),
        &quota,
        ("fixture", None),
        "tool",
        &arguments,
        None,
    )
    .await;
    assert!(overflow.is_none(), "meta refuses past the shared cap");
    let overflow_caller = (None, (Some("cap-direct-overflow"), None), Some(&client));
    let overflow_quota = direct_quota_key(overflow_caller).expect("direct still charges quota");
    let direct_overflow = super::mint_continuation(
        &state,
        super::direct_source(overflow_caller),
        &overflow_quota,
        ("fixture", None),
        "tool",
        &arguments,
        None,
    )
    .await;
    assert!(
        direct_overflow.is_none(),
        "direct refuses past the shared cap"
    );
}
