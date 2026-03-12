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
        300,
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
        300,
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
        300,
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
        300,
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
        300,
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
        300,
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
        300, // 300s buffer
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = TokenInfo {
        access_token: "tok".to_string(),
        token_type: "Bearer".to_string(),
        refresh_token: None,
        expires_at: Some(now + 200), // only 200s left, buffer is 300s
        scope: None,
        token_endpoint: None,
        client_id: None,
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
        300,
    );
    let token = TokenInfo::from_response("tok".to_string(), None, None, Some(3600), None);
    *client.current_token.write() = Some(token);

    // WHEN / THEN: 3600s remaining >> 300s buffer → no refresh yet
    assert!(!client.needs_proactive_refresh());
}
