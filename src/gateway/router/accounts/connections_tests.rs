// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The connections dispatcher where the router fixture cannot reach: a
//! browser session with no bridge client to verify it.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

use super::route;
use crate::personal_accounts::revoke_fixture::StoreDown;

fn session_config() -> crate::config::Config {
    serde_yaml::from_str(
        r"
accounts:
  schema_version: accounts.v1
  deployment: single_process
  instance_id: unit
  store_dir: /unused/store
  authority_dir: /unused/authority
  current_key_id: primary
  keys:
    primary: env:UNUSED
  adapters:
    - kind: openwebui_signed_header
      installation_id: desk
      header: x-openwebui-assertion
      issuer: open-webui
      hmac_secret_ref: env:UNUSED_HMAC
      allowed_api_key_names: [owui]
      session:
        user_endpoint: http://127.0.0.1:9/api/v1/auths/
",
    )
    .unwrap()
}

/// With no bridge client a session cookie cannot be verified, and the
/// dispatcher says the service is unavailable rather than guessing: 503, and
/// the revocation half is never reached.
#[tokio::test]
async fn a_session_cookie_without_a_bridge_client_is_unavailable() {
    // GIVEN
    let (state, _dir) = super::super::super::tests::test_router_app_state().await;
    state.live_config.set(session_config());
    let down = Arc::new(StoreDown::default());
    let router = Router::new()
        .route(
            "/connections/{account_id}",
            route(Router::new(), down.clone(), None),
        )
        .with_state(state);
    let request = Request::delete("/connections/work")
        .header("cookie", "token=session-value")
        .body(Body::empty())
        .unwrap();
    // WHEN
    let response = router.oneshot(request).await.unwrap();
    // THEN
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "unavailable", "{body}");
    assert_eq!(down.provider_calls(), 0);
}
