// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::{ResolvedAuthConfig, StreamingConfig, create_router, test_router_app_state_with};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end auth scenario read as a single sequence is the point of the test"
)]
async fn openwebui_assertion_is_checked_after_real_gateway_authentication() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join("adapter.env");
    let secret = "fixture-adapter-signing-secret-123456789";
    std::fs::write(&env_path, format!(
        "OWUI_ROUTE_HMAC={secret}\nOWUI_ROUTE_STORE=UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=\n"
    )).unwrap();
    let config: crate::config::Config = serde_yaml::from_str(&format!(
        r#"
env_files: ["{}"]
auth:
  enabled: true
  public_paths: []
  bearer_token: fixture-bearer-only
  api_keys:
    - name: owui
      key: fixture-named-api-key
    - name: other
      key: fixture-other-api-key
accounts:
  schema_version: accounts.v1
  enabled: false
  deployment: single_process
  instance_id: router-fixture
  store_dir: /unused/router-fixture-store
  authority_dir: /unused/router-fixture-authority
  current_key_id: primary
  keys:
    primary: env:OWUI_ROUTE_STORE
  adapters:
    - kind: openwebui_signed_header
      installation_id: fixture-installation
      header: x-openwebui-assertion
      issuer: open-webui
      hmac_secret_ref: env:OWUI_ROUTE_HMAC
      allowed_api_key_names: [owui]
"#,
        env_path.display()
    ))
    .unwrap();
    let auth = Arc::new(ResolvedAuthConfig::from_config(&config.auth));
    let (mut state, _store) = test_router_app_state_with(StreamingConfig::default(), config).await;
    Arc::get_mut(&mut state).unwrap().auth_config = auth;
    let router = create_router(state);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = json!({"iss":"open-webui","sub":"alice","iat":now,"exp":now+120});
    let valid = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap();
    let invalid = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(b"wrong-secret"),
    )
    .unwrap();
    for (label, credential, assertion, expected) in [
        (
            "no assertion",
            "fixture-named-api-key",
            None,
            StatusCode::OK,
        ),
        (
            "valid assertion",
            "fixture-named-api-key",
            Some(valid.as_str()),
            StatusCode::OK,
        ),
        (
            "wrong signature",
            "fixture-named-api-key",
            Some(invalid.as_str()),
            StatusCode::FORBIDDEN,
        ),
        (
            "bearer is not named key",
            "fixture-bearer-only",
            Some(valid.as_str()),
            StatusCode::FORBIDDEN,
        ),
        (
            "unlisted key",
            "fixture-other-api-key",
            Some(valid.as_str()),
            StatusCode::FORBIDDEN,
        ),
        (
            "unauthenticated",
            "unknown-key",
            Some(valid.as_str()),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "duplicate header",
            "fixture-named-api-key",
            Some(valid.as_str()),
            StatusCode::FORBIDDEN,
        ),
        (
            "conflicting identity",
            "fixture-named-api-key",
            Some(valid.as_str()),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {credential}"));
        if let Some(assertion) = assertion {
            request = request.header("x-openwebui-assertion", assertion);
        }
        if label == "duplicate header" {
            request = request.header("x-openwebui-assertion", valid.as_str());
        }
        let mut request = request
            .body(Body::from(
                json!({
                    "jsonrpc":"2.0", "id":1, "method":"initialize", "params":{
                        "protocolVersion":"2025-11-25", "capabilities":{},
                        "clientInfo":{"name":"adapter-test","version":"1"}
                    }
                })
                .to_string(),
            ))
            .unwrap();
        if label == "conflicting identity" {
            request
                .extensions_mut()
                .insert(crate::key_server::oidc::VerifiedIdentity {
                    subject: "another-user".into(),
                    email: String::new(),
                    name: None,
                    groups: Vec::new(),
                    issuer: "https://identity.invalid".into(),
                });
        }
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), expected, "{label}");
    }
}

/// Two installations behind one proxy share one assertion header, as the
/// configuration explicitly permits.
///
/// The regression this pins: a header-keyed map made the shared header count
/// twice, so EVERY request looked like a duplicate assertion and was refused,
/// and the map kept only the last installation's material, so the surviving
/// installation was the only identity anyone could assert. Both halves are
/// checked here — each installation's own signature is accepted, a signature
/// from neither is refused, and a genuinely repeated request header is still
/// refused — plus that the two installations stay DISTINCT principals, which is
/// the property the last-wins map destroyed silently rather than loudly.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end auth scenario read as a single sequence is the point of the test"
)]
async fn installations_sharing_one_header_each_verify_with_their_own_key() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join("shared-header.env");
    let desk_secret = "fixture-desk-installation-signing-secret-1";
    let laptop_secret = "fixture-laptop-installation-signing-secret-2";
    std::fs::write(
        &env_path,
        format!(
            "OWUI_DESK_HMAC={desk_secret}\nOWUI_LAPTOP_HMAC={laptop_secret}\n\
             OWUI_SHARED_STORE=UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=\n"
        ),
    )
    .unwrap();
    let config: crate::config::Config = serde_yaml::from_str(&format!(
        r#"
env_files: ["{}"]
auth:
  enabled: true
  public_paths: []
  bearer_token: fixture-bearer-only
  api_keys:
    - name: owui
      key: fixture-named-api-key
accounts:
  schema_version: accounts.v1
  enabled: false
  deployment: single_process
  instance_id: shared-header-fixture
  store_dir: /unused/shared-header-store
  authority_dir: /unused/shared-header-authority
  current_key_id: primary
  keys:
    primary: env:OWUI_SHARED_STORE
  adapters:
    - kind: openwebui_signed_header
      installation_id: desk-installation
      header: x-openwebui-assertion
      issuer: open-webui
      hmac_secret_ref: env:OWUI_DESK_HMAC
      allowed_api_key_names: [owui]
    - kind: openwebui_signed_header
      installation_id: laptop-installation
      header: x-openwebui-assertion
      issuer: open-webui
      hmac_secret_ref: env:OWUI_LAPTOP_HMAC
      allowed_api_key_names: [owui]
"#,
        env_path.display()
    ))
    .unwrap();
    let auth = Arc::new(ResolvedAuthConfig::from_config(&config.auth));
    let adapter_state = crate::gateway::openwebui_adapter::OpenWebUiAdapterState::from_config(
        &config,
        &config.env_overlay(),
    )
    .expect("two configured adapters are an adapter deployment");
    let (mut state, _store) =
        test_router_app_state_with(StreamingConfig::default(), config.clone()).await;
    Arc::get_mut(&mut state).unwrap().auth_config = auth;
    let router = create_router(state);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // The SAME subject from both installations: distinctness must come from the
    // installation namespace, not from the upstream's choice of `sub`.
    let claims = json!({"iss":"open-webui","sub":"alice","iat":now,"exp":now+120});
    let sign = |secret: &str| {
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    };
    let desk = sign(desk_secret);
    let laptop = sign(laptop_secret);
    let neither = sign("fixture-unconfigured-signing-secret-000000");

    for (label, assertions, expected) in [
        ("desk installation", vec![desk.as_str()], StatusCode::OK),
        ("laptop installation", vec![laptop.as_str()], StatusCode::OK),
        (
            "signed by neither installation",
            vec![neither.as_str()],
            StatusCode::FORBIDDEN,
        ),
        (
            "two actual assertion headers",
            vec![desk.as_str(), laptop.as_str()],
            StatusCode::FORBIDDEN,
        ),
        (
            "one assertion repeated",
            vec![desk.as_str(), desk.as_str()],
            StatusCode::FORBIDDEN,
        ),
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("authorization", "Bearer fixture-named-api-key");
        for assertion in assertions {
            request = request.header("x-openwebui-assertion", assertion);
        }
        let request = request
            .body(Body::from(
                json!({
                    "jsonrpc":"2.0", "id":1, "method":"initialize", "params":{
                        "protocolVersion":"2025-11-25", "capabilities":{},
                        "clientInfo":{"name":"shared-header-test","version":"1"}
                    }
                })
                .to_string(),
            ))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), expected, "{label}");
    }

    // Accepted is not enough: the two installations must resolve to different
    // principals, or one installation's user could act as another's.
    let resolved = |token: &str| {
        adapter_state.resolved_identity_for_test("x-openwebui-assertion", "owui", token)
    };
    let desk_identity = resolved(&desk).expect("desk assertion resolves");
    let laptop_identity = resolved(&laptop).expect("laptop assertion resolves");
    assert_eq!(desk_identity.subject, "alice");
    assert_eq!(laptop_identity.subject, "alice");
    assert_ne!(desk_identity.issuer, laptop_identity.issuer);
    assert_ne!(
        desk_identity.stable_actor_id(),
        laptop_identity.stable_actor_id()
    );
    assert!(resolved(&neither).is_none(), "unconfigured signing key");
    // An API key no installation lists resolves to nothing, so the shared
    // header did not widen the allow-list of either installation.
    assert!(
        adapter_state
            .resolved_identity_for_test("x-openwebui-assertion", "other", &desk)
            .is_none(),
        "unlisted api key"
    );
}
