// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8659 phase 1: the shared F0 agreement oracle and gateway mints.
//!
//! Every reader test compares its own reader against [`expected_api_key`]
//! over [`mints`], plus its module-local mints (stdio, key-server, OIDC).

use super::AuthenticatedClient;
use crate::security::audit::CredentialKind;

/// MIK-8659 oracle: an API key name is visible only when the client both
/// holds an API-key credential and authenticated with it.
pub(crate) fn expected_api_key(c: &AuthenticatedClient) -> Option<&str> {
    (c.authenticated && c.credential_kind == CredentialKind::ApiKey).then_some(c.name.as_str())
}

/// MIK-8659 gateway mints: bearer and API key through a real [`super::Auth`]
/// value's `validate_token`, plus dashboard, anonymous and public through
/// their real constructors. Then the bad pairs of T1b/T1e as plain struct
/// literals, each labelled, so every reader test also pins them.
pub(crate) fn mints() -> Vec<(&'static str, AuthenticatedClient)> {
    let secret_api = "mik-8659-api-key-secret";
    let secret_bearer = "mik-8659-bearer-secret";
    let auth_config = crate::config::AuthConfig {
        enabled: true,
        bearer_token: Some(secret_bearer.to_owned()),
        api_keys: vec![crate::config::ApiKeyConfig {
            key: None,
            key_sha256: Some(crate::config::api_key_digest_spec(secret_api.as_bytes())),
            expires_at: None,
            name: "k".to_owned(),
            rate_limit: 0,
            backends: vec!["*".to_owned()],
            allowed_tools: None,
            denied_tools: None,
            admin: true,
            kind: crate::config::ApiKeyKind::Shared,
        }],
        ..crate::config::AuthConfig::default()
    };
    let resolved = super::ResolvedAuthConfig::try_from_config(
        &auth_config,
        &crate::config::EnvOverlay::none(),
        crate::gateway::record_principal::TEST_RECORD_KEY,
    )
    .expect("fixture auth resolves");
    let bearer = resolved
        .validate_token(secret_bearer)
        .expect("bearer validates");
    let api_key = resolved
        .validate_token(secret_api)
        .expect("api key validates");
    let mut out = vec![
        ("bearer", bearer),
        ("api_key", api_key),
        ("dashboard", super::dashboard_client()),
        ("anonymous", super::anonymous_client()),
        ("public", super::public_client()),
        (
            "bad_unauthenticated_api_key_T1b",
            AuthenticatedClient {
                name: "k".to_owned(),
                rate_limit: 0,
                backends: vec!["*".to_owned()],
                allowed_tools: None,
                denied_tools: None,
                admin: false,
                // MIK-6704.IDENT.1a: a synthetic fixture, not an authorization path.
                principal: crate::gateway::record_principal::InternalPrincipal::new("p".to_owned()),
                quota_principal: None,
                authenticated: false,
                credential_kind: CredentialKind::ApiKey,
            },
        ),
        (
            "bad_empty_principal_T1e",
            AuthenticatedClient {
                name: "k".to_owned(),
                rate_limit: 0,
                backends: vec!["*".to_owned()],
                allowed_tools: None,
                denied_tools: None,
                admin: false,
                principal: crate::gateway::record_principal::InternalPrincipal::new(String::new()),
                quota_principal: None,
                authenticated: true,
                credential_kind: CredentialKind::ApiKey,
            },
        ),
    ];
    debug_assert_eq!(out.len(), 7, "five mints plus two bad pairs");
    out.sort_by(|a, b| a.0.cmp(b.0));
    out
}

/// Build a caller context from a client, mirroring
/// `dispatch_tools_call.rs` (api key name, credential principal,
/// authentication, credential kind; everything else anonymous).
fn context_for(client: &AuthenticatedClient) -> crate::gateway::meta_mcp::MetaMcpCallerContext<'_> {
    crate::gateway::meta_mcp::MetaMcpCallerContext {
        api_key_name: Some(client.name.as_str()),
        credential_principal: Some(client.principal.storage_form()),
        authentication: crate::gateway::meta_mcp::Authentication::of(Some(client)),
        credential_kind: CredentialKind::of(Some(client)),
        ..crate::gateway::meta_mcp::anonymous_caller()
    }
}

/// MIK-8659 T1a (GREEN): the five gateway mints agree on every F0 reader
/// reachable here: client identity, context cost key and grant key all equal
/// the oracle. The key-server, OIDC and stdio mints are pinned in their own
/// modules against the same oracle.
#[test]
fn t1a_gateway_mints_agree_on_api_key_identity() {
    for (label, client) in mints() {
        if label.starts_with("bad_") {
            continue;
        }
        let expected = expected_api_key(&client);
        assert_eq!(
            client.api_key_identity(),
            expected,
            "{label}: client api_key_identity"
        );
        let ctx = context_for(&client);
        assert_eq!(ctx.cost_key(), expected, "{label}: context cost_key");
        assert_eq!(
            ctx.scope().grant_key,
            expected,
            "{label}: context grant_key"
        );
    }
}

/// MIK-8659 T1b (RED): an unauthenticated API-key pair gives no identity
/// anywhere. `cost_key` does not check `authenticated` yet, so it reports
/// `Some("k")` and this fails.
#[test]
fn t1b_unauthenticated_api_key_gives_none_everywhere() {
    let (_, client) = mints()
        .into_iter()
        .find(|(label, _)| *label == "bad_unauthenticated_api_key_T1b")
        .expect("T1b bad pair is labelled");
    assert_eq!(expected_api_key(&client), None, "oracle pins None");
    assert_eq!(
        client.api_key_identity(),
        None,
        "client api_key_identity refuses"
    );
    let ctx = context_for(&client);
    assert_eq!(ctx.cost_key(), None, "context cost_key refuses");
    assert_eq!(ctx.scope().grant_key, None, "context grant_key refuses");
}

/// MIK-8659 T3 (GREEN): the persisted owner prefix is pinned literally, so a
/// change to the encoding fails here rather than drifting silently.
#[test]
fn t3_credential_owner_prefix_is_pinned() {
    assert_eq!(super::CREDENTIAL_OWNER_PREFIX, "credential:");
}
