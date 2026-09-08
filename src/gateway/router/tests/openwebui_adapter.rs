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
