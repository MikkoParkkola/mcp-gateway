// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6745 slice 4: `DELETE /accounts/v1/connections/{account_id}` with the
//! API credential (design §8.2, §11.2 rows T-REV, T-REV2, T-R2-4, T-R3-3,
//! T-C07a, T-C07c). Real router, auth, adapter, store and custody; only the
//! provider transport is faked (`personal_accounts::revoke_fixture`).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::super::super::create_router_with_accounts;
use super::super::{ResolvedAuthConfig, StreamingConfig, test_router_app_state_with};
use crate::personal_accounts::AccountKey;
use crate::personal_accounts::revoke_fixture::{ISSUER, RevokeFixture, Seed, grant};

const ACCOUNT: &str = "work";
const RESOURCE: &str = "https://api.fixture.test/";
const HMAC: &str = "fixture-adapter-signing-secret-123456789";
const API_KEY: &str = "fixture-named-api-key";

fn key(subject: &str) -> AccountKey {
    AccountKey {
        principal_authority: "openwebui-adapter:20:fixture-installation".into(),
        principal_subject: subject.into(),
        backend_id: ACCOUNT.into(),
        resource: RESOURCE.into(),
        oauth_issuer: ISSUER.into(),
    }
}

fn config(env: &std::path::Path, hosted: bool) -> crate::config::Config {
    let hosted = if hosted {
        "  hosted:\n    public_origin: https://chat.fixture.test\n    return_paths: [/]\n"
    } else {
        ""
    };
    serde_yaml::from_str(&format!(
        r#"
env_files: ["{env}"]
auth:
  enabled: true
  public_paths: []
  api_keys:
    - name: owui
      key: {API_KEY}
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
  descriptors:
    {ACCOUNT}:
      mode: personal_managed
      provider: fixture
      resource: {RESOURCE}
      issuer: {ISSUER}
{hosted}"#,
        env = env.display()
    ))
    .unwrap()
}

/// One gateway: router, custody fixture, and the state behind the router.
struct Gateway {
    router: axum::Router,
    fixture: RevokeFixture,
    state: Arc<crate::gateway::router::AppState>,
    _dir: tempfile::TempDir,
}

async fn gateway(
    hosted: bool,
    seeds: &[(AccountKey, crate::personal_accounts::GrantRecord, Seed)],
) -> Gateway {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join("adapter.env");
    std::fs::write(
        &env,
        format!("OWUI_ROUTE_HMAC={HMAC}\nOWUI_ROUTE_STORE=UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=\n"),
    )
    .unwrap();
    let config = config(&env, hosted);
    let auth = Arc::new(ResolvedAuthConfig::from_config(&config.auth));
    let (mut state, _store) = test_router_app_state_with(StreamingConfig::default(), config).await;
    let log = crate::security::transparency_log::TransparencyLogConfig {
        enabled: true,
        path: dir.path().join("audit.ndjson").display().to_string(),
        key_id: "fixture".into(),
        shared_secret: String::new(),
    };
    let logger = crate::security::TransparencyLogger::open(Arc::new(log)).unwrap();
    {
        let state = Arc::get_mut(&mut state).unwrap();
        state.auth_config = auth;
        state.transparency_log = Some(Arc::new(logger));
    }
    let fixture = RevokeFixture::start(ACCOUNT, RESOURCE, seeds).await;
    let router = create_router_with_accounts(Arc::clone(&state), None, Some(fixture.revocation()));
    Gateway {
        router,
        fixture,
        state,
        _dir: dir,
    }
}

fn assertion(subject: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = json!({"iss":"open-webui","sub":subject,"iat":now,"exp":now+120});
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(HMAC.as_bytes()),
    )
    .unwrap()
}

/// DELETE as `subject` (or anonymously), returning status and JSON body.
async fn delete(gw: &Gateway, subject: Option<&str>, account: &str) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("DELETE")
        .uri(format!("/accounts/v1/connections/{account}"));
    if let Some(subject) = subject {
        request = request
            .header("authorization", format!("Bearer {API_KEY}"))
            .header("x-openwebui-assertion", assertion(subject));
    }
    let response = gw
        .router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn sent(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(token, hint)| ((*token).to_string(), (*hint).to_string()))
        .collect()
}

const A_REFRESH: &str = "synthetic-alice-refresh-4b2c";
const A_ACCESS: &str = "synthetic-alice-access-7d1e";

fn both() -> Vec<(String, String)> {
    sent(&[(A_REFRESH, "refresh_token"), (A_ACCESS, "access_token")])
}

fn revoked_body(provider_revocation: &str) -> Value {
    json!({"schema_version": 1, "account_id": ACCOUNT, "status": "revoked",
           "provider_revocation": provider_revocation})
}

/// T-REV (API variant): A's revoke reaches the provider and leaves B alone.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_route_connected_confirms_and_isolates_other_principal() {
    // GIVEN: A and B both connected
    let gw = gateway(
        true,
        &[
            (key("alice"), grant("alice"), Seed::Connected),
            (key("bob"), grant("bob"), Seed::Connected),
        ],
    )
    .await;
    // WHEN
    let (status, body) = delete(&gw, Some("alice"), ACCOUNT).await;
    // THEN
    assert_eq!((status, body), (StatusCode::OK, revoked_body("confirmed")));
    assert_eq!(gw.fixture.received(), both());
    assert_eq!(gw.fixture.state(&key("alice")).await, "revoked");
    assert_eq!(gw.fixture.state(&key("bob")).await, "connected");
}

/// T-REV2: a provider failure is reported and never un-tombstones.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_route_provider_503_reports_failed_and_stays_revoked() {
    // GIVEN
    let gw = gateway(true, &[(key("alice"), grant("alice"), Seed::Connected)]).await;
    gw.fixture.answer(503);
    // WHEN
    let (status, body) = delete(&gw, Some("alice"), ACCOUNT).await;
    // THEN
    assert_eq!((status, body), (StatusCode::OK, revoked_body("failed")));
    assert_eq!(gw.fixture.received(), both(), "every token is tried after a failure");
    assert_eq!(gw.fixture.state(&key("alice")).await, "revoked");
}

/// T-R2-4 and T-R3-3: both `ReconnectRequired` causes still revoke both
/// tokens, refresh first; an already revoked grant sends nothing.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_route_reconnect_required_sends_both_tokens_refresh_first() {
    for seed in [Seed::InvalidGrant, Seed::DescriptorFenced] {
        // GIVEN
        let gw = gateway(true, &[(key("alice"), grant("alice"), seed)]).await;
        // WHEN
        let (status, body) = delete(&gw, Some("alice"), ACCOUNT).await;
        // THEN
        assert_eq!(
            (status, body),
            (StatusCode::OK, revoked_body("confirmed")),
            "{seed:?}"
        );
        assert_eq!(gw.fixture.received(), both(), "{seed:?}");
        // AND WHEN: revoked again, there is nothing left to send
        let (status, body) = delete(&gw, Some("alice"), ACCOUNT).await;
        assert_eq!(
            (status, body),
            (StatusCode::OK, revoked_body("not_applicable"))
        );
        assert_eq!(gw.fixture.received(), both(), "no second request");
    }
}

/// T-R2-4, third case: a grant revoked before the call yields `not_applicable`.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_route_already_revoked_is_not_applicable_and_sends_nothing() {
    let gw = gateway(true, &[(key("alice"), grant("alice"), Seed::Revoked)]).await;
    let (status, body) = delete(&gw, Some("alice"), ACCOUNT).await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, revoked_body("not_applicable"))
    );
    assert!(gw.fixture.received().is_empty());
}

/// T-C07a (DELETE part): anonymous is 401; B naming A's account revokes only
/// B's own (absent) key, and A stays connected.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_route_other_principal_cannot_reach_a_and_anonymous_is_401() {
    // GIVEN: only A connected
    let gw = gateway(true, &[(key("alice"), grant("alice"), Seed::Connected)]).await;
    // WHEN / THEN: anonymous
    let (status, _) = delete(&gw, None, ACCOUNT).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // WHEN / THEN: B with A's account id
    let (status, body) = delete(&gw, Some("bob"), ACCOUNT).await;
    assert_eq!(
        (status, body),
        (StatusCode::OK, revoked_body("not_applicable"))
    );
    assert!(gw.fixture.received().is_empty(), "A's tokens never sent");
    assert_eq!(gw.fixture.state(&key("alice")).await, "connected");
}

/// T-C07c: the audit write fails after the tombstone; 503, still revoked.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_route_audit_failure_is_503_and_keeps_the_tombstone() {
    // GIVEN
    let gw = gateway(true, &[(key("alice"), grant("alice"), Seed::Connected)]).await;
    gw.state
        .transparency_log
        .as_ref()
        .unwrap()
        .fail_next_append_for_test();
    // WHEN
    let (status, body) = delete(&gw, Some("alice"), ACCOUNT).await;
    // THEN
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "audit_unavailable");
    assert_eq!(body["local_status"], "revoked");
    assert_eq!(gw.fixture.state(&key("alice")).await, "revoked");
    assert!(
        gw.fixture.received().is_empty(),
        "no provider call past a failed audit"
    );
}

/// An account id with no managed descriptor is `not_found`; nothing is touched.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_route_undeclared_account_is_404_and_touches_nothing() {
    let gw = gateway(true, &[(key("alice"), grant("alice"), Seed::Connected)]).await;
    let (status, body) = delete(&gw, Some("alice"), "nope").await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::NOT_FOUND, json!("not_found"))
    );
    assert_eq!(gw.fixture.state(&key("alice")).await, "connected");
}

/// Without `accounts.hosted` the route is not mounted (green at red: the
/// stub also mounts only under `hosted`).
#[tokio::test(flavor = "multi_thread")]
async fn revoke_route_without_hosted_is_not_mounted() {
    let gw = gateway(false, &[(key("alice"), grant("alice"), Seed::Connected)]).await;
    let (status, _) = delete(&gw, Some("alice"), ACCOUNT).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(gw.fixture.state(&key("alice")).await, "connected");
}
