// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! RFC 8707 resource indicator on the authorize, token-exchange, refresh and client-credentials requests.

use super::*;

// =========================================================================
// RFC 8707 Resource Indicator (issue #369)
// =========================================================================

fn resource_test_client(resource_url: &str) -> OAuthClient {
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    OAuthClient::new(
        Client::new(),
        "res-test".to_string(),
        resource_url.to_string(),
        vec!["openid".to_string()],
        storage,
        OAuthClientConfig {
            token_refresh_buffer_secs: 300,
            ..Default::default()
        },
    )
}

fn protected_resource(resource: &str) -> ProtectedResourceMetadata {
    ProtectedResourceMetadata {
        resource: resource.to_string(),
        authorization_servers: vec![],
        bearer_methods_supported: vec![],
        scopes_supported: vec![],
    }
}

/// The authorization URL MUST carry the RFC 8707 `resource` parameter, using
/// the canonical identifier from discovered protected-resource metadata. This
/// is the exact regression from issue #369: without it, strict providers
/// (e.g. kapa.ai) reject the flow with `server_error`.
#[test]
fn authorize_url_includes_resource_indicator_from_metadata() {
    let mut client = resource_test_client("https://influxdb-docs.mcp.kapa.ai");
    client.resource_metadata = Some(protected_resource("https://influxdb-docs.mcp.kapa.ai/"));

    let url = client
        .build_authorize_url(
            "https://mcp.kapa.ai/auth/public/authorize",
            "client-abc",
            "http://localhost:36721/oauth/callback",
            "state-xyz",
            "challenge-123",
        )
        .expect("URL should build");

    let resource = url
        .query_pairs()
        .find(|(k, _)| k == "resource")
        .map(|(_, v)| v.into_owned());
    assert_eq!(
        resource.as_deref(),
        Some("https://influxdb-docs.mcp.kapa.ai/"),
        "authorize URL must include the RFC 8707 resource indicator (issue #369)"
    );

    // Sanity: the pre-existing params survive the extraction refactor.
    let keys: Vec<String> = url.query_pairs().map(|(k, _)| k.into_owned()).collect();
    for expected in [
        "response_type",
        "client_id",
        "redirect_uri",
        "state",
        "code_challenge",
        "code_challenge_method",
        "scope",
        "resource",
    ] {
        assert!(keys.contains(&expected.to_string()), "missing {expected}");
    }
}

/// When protected-resource metadata was never discovered, the indicator falls
/// back to the configured MCP endpoint URL rather than being dropped.
#[test]
fn authorize_url_resource_falls_back_to_endpoint_url() {
    let client = resource_test_client("https://example.test/mcp");

    let url = client
        .build_authorize_url(
            "https://auth.example.test/authorize",
            "cid",
            "http://localhost:5000/oauth/callback",
            "st",
            "ch",
        )
        .expect("URL should build");

    let resource = url
        .query_pairs()
        .find(|(k, _)| k == "resource")
        .map(|(_, v)| v.into_owned());
    assert_eq!(resource.as_deref(), Some("https://example.test/mcp"));
}

/// Metadata `resource` wins over the raw endpoint URL when both are available.
#[test]
fn resource_indicator_prefers_metadata_over_url() {
    let mut client = resource_test_client("https://raw.example.test/mcp");
    assert_eq!(client.resource_indicator(), "https://raw.example.test/mcp");

    client.resource_metadata = Some(protected_resource("https://canonical.example.test/"));
    assert_eq!(
        client.resource_indicator(),
        "https://canonical.example.test/"
    );
}

fn param<'a>(params: &'a [(&'static str, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.as_str())
}

fn secret_client(resource_url: &str, secret: &str) -> OAuthClient {
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    OAuthClient::new(
        Client::new(),
        "res-test".to_string(),
        resource_url.to_string(),
        vec!["openid".to_string()],
        storage,
        OAuthClientConfig {
            client_secret: Some(secret.to_string()),
            token_refresh_buffer_secs: 300,
            ..Default::default()
        },
    )
}

/// The `authorization_code` token-exchange body MUST carry `resource` (issue
/// #369) alongside the standard grant params.
#[test]
fn token_exchange_params_include_resource() {
    let mut client = resource_test_client("https://mcp.example.test/");
    client.resource_metadata = Some(protected_resource("https://canonical.example.test/"));

    let params = client.token_exchange_params(
        "auth-code",
        "http://localhost:9/oauth/callback",
        "cid",
        "verifier",
    );

    assert_eq!(param(&params, "grant_type"), Some("authorization_code"));
    assert_eq!(param(&params, "code"), Some("auth-code"));
    assert_eq!(param(&params, "code_verifier"), Some("verifier"));
    assert_eq!(
        param(&params, "resource"),
        Some("https://canonical.example.test/"),
        "token exchange must send the RFC 8707 resource indicator"
    );
    // No secret configured -> no client_secret leaked into the body.
    assert_eq!(param(&params, "client_secret"), None);
}

/// The `refresh_token` body MUST carry `resource` so refreshed tokens stay
/// audience-bound (issue #369), and forward a configured `client_secret`.
#[test]
fn refresh_params_include_resource_and_secret() {
    let client = secret_client("https://mcp.example.test/", "s3cr3t");

    let params = client.refresh_params("refresh-abc", "cid");

    assert_eq!(param(&params, "grant_type"), Some("refresh_token"));
    assert_eq!(param(&params, "refresh_token"), Some("refresh-abc"));
    assert_eq!(param(&params, "client_secret"), Some("s3cr3t"));
    assert_eq!(
        param(&params, "resource"),
        Some("https://mcp.example.test/"),
        "refresh must send the RFC 8707 resource indicator"
    );
}

/// The `client_credentials` body MUST carry `resource` — the exact gap the
/// external review caught before ship (issue #369).
#[test]
fn client_credentials_params_include_resource() {
    let mut client = resource_test_client("https://mcp.example.test/");
    client.resource_metadata = Some(protected_resource("https://canonical.example.test/"));

    let params = client.client_credentials_params("cid");

    assert_eq!(param(&params, "grant_type"), Some("client_credentials"));
    assert_eq!(param(&params, "client_id"), Some("cid"));
    assert_eq!(param(&params, "scope"), Some("openid"));
    assert_eq!(
        param(&params, "resource"),
        Some("https://canonical.example.test/"),
        "client_credentials must send the RFC 8707 resource indicator"
    );
}
