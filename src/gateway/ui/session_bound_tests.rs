// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The session bound a dashboard link or the sign-in form mints with, and the
//! link's order: the credential's binding before the bind-address check.

use super::mik_8659_dashboard_tests::t1f_app_state;

/// The static bearer of [`one_admin_key`]'s table.
const ORDER_BEARER: &str = "order-static-bearer";

/// A resolved table with the static bearer and one admin API key, `secret`.
fn one_admin_key(
    name: &str,
    secret: &str,
) -> std::sync::Arc<crate::gateway::auth::ResolvedAuthConfig> {
    let auth = crate::config::AuthConfig {
        enabled: true,
        bearer_token: Some(ORDER_BEARER.to_owned()),
        api_keys: vec![crate::config::ApiKeyConfig {
            key: None,
            key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
            expires_at: None,
            name: name.to_owned(),
            rate_limit: 0,
            backends: vec!["*".to_owned()],
            allowed_tools: None,
            denied_tools: None,
            admin: true,
            kind: crate::config::ApiKeyKind::Shared,
            ..Default::default()
        }],
        ..crate::config::AuthConfig::default()
    };
    std::sync::Arc::new(
        crate::gateway::auth::ResolvedAuthConfig::try_from_config(
            &auth,
            &crate::config::EnvOverlay::none(),
            crate::gateway::record_principal::TEST_RECORD_KEY,
        )
        .expect("fixture auth resolves"),
    )
}

/// The credential's binding is judged before the bind-address check. On a
/// network bind, an API-key client that cannot be bound is refused (403),
/// while the same key, bindable, reaches the bind check (409).
#[tokio::test]
async fn an_unbindable_client_is_refused_before_the_bind_address_check() {
    use std::sync::Arc;
    let secret = "order-unbindable-admin-secret";
    let auth_config = one_admin_key("k", secret);
    let (real, named) = auth_config
        .validate_token_with_origin(secret)
        .expect("admin key validates");
    let mut config = crate::config::Config::default();
    // TEST-NET-1: a network address, neither loopback nor a wildcard.
    config.server.host = "192.0.2.10".to_owned();
    let store_dir = tempfile::tempdir().expect("task store dir");
    let state = t1f_app_state(&auth_config, store_dir.path(), config).await;
    let link = |client: crate::gateway::auth::AuthenticatedClient,
                named: Option<crate::gateway::auth::NamedApiKey>| {
        super::dashboard_link(
            axum::extract::State(Arc::clone(&state)),
            axum::extract::Extension(state.live_config.generation()),
            named.map(axum::extract::Extension),
            super::super::guard::Guard::for_route(
                crate::gateway::routes::UI_DASHBOARD_LINK,
                &axum::http::Method::POST,
                Some(client),
            ),
        )
    };
    // Premise: the bind decides for a bindable client, so the 403s below
    // are the binding's refusals and not the fixture's.
    assert_eq!(
        link(real.clone(), named.clone()).await.status(),
        axum::http::StatusCode::CONFLICT,
        "a bindable admin key on a network bind"
    );
    let mut no_quota = real.clone();
    no_quota.quota_principal = None;
    assert!(
        super::super::guard::decide(
            super::super::access_table::Need::AdminKeyLink,
            Some(&no_quota)
        )
        .is_ok(),
        "premise: the guard admits an admin API key with no quota identity"
    );
    assert_eq!(
        link(no_quota, named).await.status(),
        axum::http::StatusCode::FORBIDDEN,
        "no quota identity: refused before the bind-address check"
    );
    assert_eq!(
        link(real, None).await.status(),
        axum::http::StatusCode::FORBIDDEN,
        "no matched secret: refused before the bind-address check"
    );
}

/// `bound_for`, which the sign-in form and the dashboard link share. The
/// matched admin key binds its quota identity and the fingerprint of the
/// secret it matched; an API-key client missing either, or not in the
/// table, binds nothing (`None`: it may not mint); the static bearer binds
/// nothing and may mint.
#[test]
fn bound_for_binds_the_matched_key_and_refuses_an_unbindable_one() {
    let secret = "bound-for-admin-secret";
    let auth_config = one_admin_key("k", secret);
    let (real, named) = auth_config
        .validate_token_with_origin(secret)
        .expect("admin key validates");
    let named = named.expect("an API-key match carries its secret's record");
    let bound = super::bound_for(&auth_config, &real, Some(&named)).expect("the matched key binds");
    assert!(bound.not_after.is_none(), "the key has no expiry");
    assert_eq!(
        bound.key,
        Some(crate::gateway::auth::MintingKey {
            quota: real
                .quota_principal
                .clone()
                .expect("a key's quota identity"),
            digest_tag: named.digest_tag().to_owned(),
        }),
    );
    let mut no_quota = real.clone();
    no_quota.quota_principal = None;
    assert!(super::bound_for(&auth_config, &no_quota, Some(&named)).is_none());
    assert!(super::bound_for(&auth_config, &real, None).is_none());
    let other_secret = "bound-for-other-secret";
    let other = one_admin_key("other", other_secret);
    let (stranger, stranger_named) = other
        .validate_token_with_origin(other_secret)
        .expect("the other table's key validates");
    assert!(
        super::bound_for(&auth_config, &stranger, stranger_named.as_ref()).is_none(),
        "a key this table does not hold cannot prove its expiry"
    );
    let (bearer, bearer_named) = auth_config
        .validate_token_with_origin(ORDER_BEARER)
        .expect("the static bearer validates");
    assert!(
        bearer_named.is_none(),
        "premise: the bearer matches no API key"
    );
    let unbound =
        super::bound_for(&auth_config, &bearer, None).expect("the static bearer may mint");
    assert!(unbound.not_after.is_none() && unbound.key.is_none());
}

/// The dashboard link names the loopback a wildcard bind serves. A mapped
/// IPv4 wildcard (`::ffff:0.0.0.0`) serves IPv4, so its link is IPv4 loopback,
/// as `0.0.0.0`'s is; the IPv6 wildcard's is IPv6 loopback, bracketed or not.
#[test]
fn a_mapped_or_bracketed_wildcard_bind_links_to_its_loopback() {
    for (host, link) in [
        ("::ffff:0.0.0.0", "127.0.0.1:39400"),
        ("0.0.0.0", "127.0.0.1:39400"),
        ("::", "[::1]:39400"),
        ("[::]", "[::1]:39400"),
        // An IPv4 wildcard in brackets: the link's own strip gives the bare
        // address its family (the shared wildcard test's strip is pinned by
        // the router's classifier table).
        ("[0.0.0.0]", "127.0.0.1:39400"),
    ] {
        assert_eq!(super::loopback_authority(host, 39400), link, "{host}");
    }
}
