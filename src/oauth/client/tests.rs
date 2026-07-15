// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

// =========================================================================
// PKCE generation
// =========================================================================

#[test]
fn test_pkce_generation() {
    let (verifier, challenge) = generate_pkce();

    // Verifier should be base64url encoded
    assert!(verifier.len() >= 43);
    assert!(!verifier.contains('+'));
    assert!(!verifier.contains('/'));

    // Challenge should be different from verifier (it's hashed)
    assert_ne!(verifier, challenge);
}

#[test]
fn pkce_verifier_is_base64url_safe() {
    for _ in 0..10 {
        let (verifier, challenge) = generate_pkce();
        // base64url characters only
        assert!(!verifier.contains('+'));
        assert!(!verifier.contains('/'));
        assert!(!verifier.contains('='));
        assert!(!challenge.contains('+'));
        assert!(!challenge.contains('/'));
        assert!(!challenge.contains('='));
    }
}

#[test]
fn pkce_challenge_is_sha256_of_verifier() {
    let (verifier, challenge) = generate_pkce();
    // Manually compute expected challenge
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let expected_bytes = hasher.finalize();
    let expected = URL_SAFE_NO_PAD.encode(expected_bytes);
    assert_eq!(challenge, expected);
}

#[test]
fn pkce_generates_unique_values() {
    let (v1, c1) = generate_pkce();
    let (v2, c2) = generate_pkce();
    assert_ne!(v1, v2, "Two PKCE verifiers should be unique");
    assert_ne!(c1, c2, "Two PKCE challenges should be unique");
}

// =========================================================================
// State generation
// =========================================================================

#[test]
fn state_is_base64url_safe() {
    for _ in 0..10 {
        let state = generate_state();
        assert!(!state.contains('+'));
        assert!(!state.contains('/'));
        assert!(!state.contains('='));
        assert!(!state.is_empty());
    }
}

#[test]
fn state_generates_unique_values() {
    let s1 = generate_state();
    let s2 = generate_state();
    assert_ne!(s1, s2);
}

#[test]
fn state_has_sufficient_length() {
    let state = generate_state();
    // 16 random bytes -> 22 base64url chars
    assert!(
        state.len() >= 20,
        "State should be at least 20 chars, got {}",
        state.len()
    );
}

// =========================================================================
// Client ID generation
// =========================================================================

#[test]
fn client_id_is_base64url_safe() {
    let id = generate_client_id();
    assert!(!id.contains('+'));
    assert!(!id.contains('/'));
    assert!(!id.contains('='));
}

#[test]
fn client_id_generates_unique_values() {
    let id1 = generate_client_id();
    let id2 = generate_client_id();
    assert_ne!(id1, id2);
}

// =========================================================================
// OAuthClient construction and has_valid_token
// =========================================================================

#[test]
fn new_client_has_no_valid_token() {
    let storage =
        Arc::new(TokenStorage::new(std::env::temp_dir().join("oauth_test_no_token")).unwrap());
    let client = OAuthClient::new(
        Client::new(),
        "test-backend".to_string(),
        "http://localhost:8080".to_string(),
        vec!["read".to_string()],
        storage,
        OAuthClientConfig {
            token_refresh_buffer_secs: 300,
            ..Default::default()
        },
    );
    assert!(!client.has_valid_token());
}

#[test]
fn client_with_valid_token_returns_true() {
    let storage =
        Arc::new(TokenStorage::new(std::env::temp_dir().join("oauth_test_valid_token")).unwrap());
    let client = OAuthClient::new(
        Client::new(),
        "test-backend".to_string(),
        "http://localhost:8080".to_string(),
        vec![],
        storage,
        OAuthClientConfig {
            token_refresh_buffer_secs: 300,
            ..Default::default()
        },
    );

    // Inject a non-expired token
    let token = TokenInfo::from_response(
        "access_token_123".to_string(),
        Some("Bearer".to_string()),
        None,
        Some(3600), // expires in 1 hour
        None,
    );
    *client.current_token.write() = Some(token);

    assert!(client.has_valid_token());
}

#[test]
fn client_with_expired_token_returns_false() {
    let storage =
        Arc::new(TokenStorage::new(std::env::temp_dir().join("oauth_test_expired_token")).unwrap());
    let client = OAuthClient::new(
        Client::new(),
        "test-backend".to_string(),
        "http://localhost:8080".to_string(),
        vec![],
        storage,
        OAuthClientConfig {
            token_refresh_buffer_secs: 300,
            ..Default::default()
        },
    );

    // Inject an expired token
    let mut token =
        TokenInfo::from_response("expired_token".to_string(), None, None, Some(3600), None);
    token.expires_at = Some(0); // expired long ago
    *client.current_token.write() = Some(token);

    assert!(!client.has_valid_token());
}

// =========================================================================
// backend_name accessor
// =========================================================================

#[test]
fn backend_name_returns_configured_name() {
    let storage =
        Arc::new(TokenStorage::new(std::env::temp_dir().join("oauth_test_backend_name")).unwrap());
    let client = OAuthClient::new(
        Client::new(),
        "my-service".to_string(),
        "http://localhost:8080".to_string(),
        vec![],
        storage,
        OAuthClientConfig {
            token_refresh_buffer_secs: 300,
            ..Default::default()
        },
    );
    assert_eq!(client.backend_name(), "my-service");
}

// =========================================================================
// needs_proactive_refresh
// =========================================================================

#[test]
fn needs_proactive_refresh_false_when_no_token() {
    // GIVEN: client with no token
    let storage = Arc::new(
        TokenStorage::new(std::env::temp_dir().join("oauth_test_refresh_no_token")).unwrap(),
    );
    let client = OAuthClient::new(
        Client::new(),
        "backend".to_string(),
        "http://localhost".to_string(),
        vec![],
        storage,
        OAuthClientConfig {
            token_refresh_buffer_secs: 300,
            ..Default::default()
        },
    );

    // WHEN / THEN: no token means no proactive refresh needed
    assert!(!client.needs_proactive_refresh());
}

#[test]
fn needs_proactive_refresh_false_when_token_no_expiry() {
    // GIVEN: token with no expiry (never expires)
    let storage = Arc::new(
        TokenStorage::new(std::env::temp_dir().join("oauth_test_refresh_no_expiry")).unwrap(),
    );
    let client = OAuthClient::new(
        Client::new(),
        "backend".to_string(),
        "http://localhost".to_string(),
        vec![],
        storage,
        OAuthClientConfig {
            token_refresh_buffer_secs: 300,
            ..Default::default()
        },
    );
    let token = TokenInfo::from_response("tok".to_string(), None, None, None, None);
    *client.current_token.write() = Some(token);

    // WHEN / THEN: no expiry → never needs refresh
    assert!(!client.needs_proactive_refresh());
}

#[test]
fn needs_proactive_refresh_true_when_within_buffer() {
    // GIVEN: token expiring in 200s with a 300s buffer
    let storage = Arc::new(
        TokenStorage::new(std::env::temp_dir().join("oauth_test_refresh_within_buf")).unwrap(),
    );
    let client = OAuthClient::new(
        Client::new(),
        "backend".to_string(),
        "http://localhost".to_string(),
        vec![],
        storage,
        OAuthClientConfig {
            token_refresh_buffer_secs: 300,
            ..Default::default()
        },
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = TokenInfo {
        expires_at: Some(now + 200), // only 200s left, buffer is 300s
        ..TokenInfo::from_response("tok".to_string(), None, None, None, None)
    };
    *client.current_token.write() = Some(token);

    // WHEN / THEN: 200s remaining < 300s buffer → should refresh
    assert!(client.needs_proactive_refresh());
}

#[test]
fn needs_proactive_refresh_false_when_outside_buffer() {
    // GIVEN: token expiring in 1h with 300s buffer
    let storage = Arc::new(
        TokenStorage::new(std::env::temp_dir().join("oauth_test_refresh_outside_buf")).unwrap(),
    );
    let client = OAuthClient::new(
        Client::new(),
        "backend".to_string(),
        "http://localhost".to_string(),
        vec![],
        storage,
        OAuthClientConfig {
            token_refresh_buffer_secs: 300,
            ..Default::default()
        },
    );
    let token = TokenInfo::from_response("tok".to_string(), None, None, Some(3600), None);
    *client.current_token.write() = Some(token);

    // WHEN / THEN: 3600s remaining >> 300s buffer -> no refresh yet
    assert!(!client.needs_proactive_refresh());
}

// =========================================================================
// purge_client_id_if_invalid -- static vs dynamic clients
// =========================================================================

#[test]
fn purge_keeps_configured_static_client_on_invalid_client() {
    // GIVEN: a client with a configured client_secret. Its client_id is
    // operator-supplied static config (Slack/Figma style), NOT a dynamic
    // registration -- purging it would delete valid config.
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let client = OAuthClient::new(
        Client::new(),
        "slack".to_string(),
        "http://localhost".to_string(),
        vec![],
        Arc::clone(&storage),
        OAuthClientConfig {
            client_id: Some("configured-static-id".to_string()),
            client_secret: Some("configured-secret".to_string()),
            token_refresh_buffer_secs: 300,
            ..Default::default()
        },
    );
    storage
        .save_client_id("slack", "http://localhost", "configured-static-id")
        .unwrap();

    // WHEN: the server rejects the token request with invalid_client.
    client.purge_client_id_if_invalid(r#"{"error":"invalid_client"}"#);

    // THEN: the configured id survives in memory AND on disk.
    assert_eq!(
        client.client_id.read().clone(),
        Some("configured-static-id".to_string()),
        "configured static client_id must NOT be purged from memory"
    );
    assert_eq!(
        storage.load_client_id("slack", "http://localhost"),
        Some("configured-static-id".to_string()),
        "configured static client_id file must NOT be deleted"
    );
}

#[test]
fn purge_keeps_public_configured_client_without_secret_on_invalid_client() {
    // GIVEN: an operator-configured PUBLIC client -- client_id set via
    // config, no client_secret (e.g. a native/PKCE-only app registration).
    // Defect 2 (MIK-6750 r7): the old `client_secret.is_some()` guard did
    // NOT protect this case -- an invalid_client rejection erased the
    // operator's configured id and the next auth attempt used a
    // generated/DCR id instead of the one the operator configured.
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let client = OAuthClient::new(
        Client::new(),
        "public-app".to_string(),
        "http://localhost".to_string(),
        vec![],
        Arc::clone(&storage),
        OAuthClientConfig {
            client_id: Some("configured-public-id".to_string()),
            client_secret: None,
            token_refresh_buffer_secs: 300,
            ..Default::default()
        },
    );

    // WHEN: the server rejects the token request with invalid_client.
    client.purge_client_id_if_invalid(r#"{"error":"invalid_client"}"#);

    // THEN: the configured id survives -- it is operator config, not a
    // dynamic registration, regardless of client_secret presence.
    assert_eq!(
        client.client_id.read().clone(),
        Some("configured-public-id".to_string()),
        "configured public (no-secret) client_id must NOT be purged"
    );
}

#[test]
fn purge_clears_dynamically_registered_client_on_invalid_client() {
    // GIVEN: a client_id obtained via Dynamic Client Registration -- set the
    // way `ensure_client_id_with_redirect`/`restore_persisted_client_id`
    // would (client_id + `ClientIdSource::Registered` together), NOT via
    // `OAuthClientConfig`. Driving this through config (as the pre-fix test
    // did) is indistinguishable from the Defect 2 scenario above and no
    // longer represents "dynamic" after the provenance fix.
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let client = OAuthClient::new(
        Client::new(),
        "dyn".to_string(),
        "http://localhost".to_string(),
        vec![],
        Arc::clone(&storage),
        OAuthClientConfig {
            client_secret: None,
            token_refresh_buffer_secs: 300,
            ..Default::default()
        },
    );
    storage
        .save_client_id("dyn", "http://localhost", "dynamic-id")
        .unwrap();
    *client.client_id.write() = Some("dynamic-id".to_string());
    *client.client_id_source.write() = Some(ClientIdSource::Registered);

    // WHEN: the server rejects the token request with invalid_client.
    client.purge_client_id_if_invalid("error=invalid_client&error_description=rejected");

    // THEN: the stale dynamic registration is purged from memory AND disk so
    // the next attempt re-registers.
    assert!(
        client.client_id.read().is_none(),
        "dynamic client_id must be purged from memory"
    );
    assert_eq!(
        storage.load_client_id("dyn", "http://localhost"),
        None,
        "dynamic client_id file must be deleted"
    );
}

#[test]
fn restore_persisted_client_id_tags_loaded_id_as_registered_and_purgeable() {
    // GIVEN: no operator-configured client_id, but a prior Dynamic Client
    // Registration persisted to disk (as `ensure_client_id_with_redirect`
    // would have done on an earlier run).
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    storage
        .save_client_id("dyn", "http://localhost", "persisted-dyn-id")
        .unwrap();
    let client = OAuthClient::new(
        Client::new(),
        "dyn".to_string(),
        "http://localhost".to_string(),
        vec![],
        Arc::clone(&storage),
        OAuthClientConfig {
            client_secret: None,
            token_refresh_buffer_secs: 300,
            ..Default::default()
        },
    );
    assert!(
        client.client_id.read().is_none(),
        "precondition: no operator-configured client_id"
    );

    // WHEN: `initialize()`'s restore step loads the persisted id.
    client.restore_persisted_client_id();

    // THEN: the loaded id is tagged Registered, not Configured, so a later
    // invalid_client rejection can purge and re-register it.
    assert_eq!(
        client.client_id.read().clone(),
        Some("persisted-dyn-id".to_string())
    );
    client.purge_client_id_if_invalid(r#"{"error":"invalid_client"}"#);
    assert!(
        client.client_id.read().is_none(),
        "an id restored from a prior DCR must be purgeable"
    );
}

#[test]
fn restore_persisted_client_id_never_overwrites_configured_id() {
    // GIVEN: an operator-configured client_id, AND (pathologically) a
    // different id sitting in the client_id storage file.
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    storage
        .save_client_id("cfg", "http://localhost", "stale-on-disk-id")
        .unwrap();
    let client = OAuthClient::new(
        Client::new(),
        "cfg".to_string(),
        "http://localhost".to_string(),
        vec![],
        Arc::clone(&storage),
        OAuthClientConfig {
            client_id: Some("configured-id".to_string()),
            client_secret: None,
            token_refresh_buffer_secs: 300,
            ..Default::default()
        },
    );

    // WHEN: `initialize()`'s restore step runs.
    client.restore_persisted_client_id();

    // THEN: the configured id is untouched -- restore is a no-op when a
    // client_id is already set -- and it remains non-purgeable.
    assert_eq!(
        client.client_id.read().clone(),
        Some("configured-id".to_string())
    );
    client.purge_client_id_if_invalid(r#"{"error":"invalid_client"}"#);
    assert_eq!(
        client.client_id.read().clone(),
        Some("configured-id".to_string()),
        "configured client_id must survive purge even with a stale disk record"
    );
}

#[test]
fn purge_is_noop_without_invalid_client_marker() {
    // GIVEN: any client with a persisted id.
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let client = OAuthClient::new(
        Client::new(),
        "dyn".to_string(),
        "http://localhost".to_string(),
        vec![],
        Arc::clone(&storage),
        OAuthClientConfig {
            client_id: Some("keep-me".to_string()),
            client_secret: None,
            token_refresh_buffer_secs: 300,
            ..Default::default()
        },
    );

    // WHEN: the error body is unrelated (e.g. invalid_grant).
    client.purge_client_id_if_invalid(r#"{"error":"invalid_grant"}"#);

    // THEN: nothing is purged.
    assert_eq!(client.client_id.read().clone(), Some("keep-me".to_string()));
}

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
