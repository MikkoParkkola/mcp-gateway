// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 part 2 (P2), T16: the control-plane grant inventory on a host
//! clock that reads before 1970. Grant status is judged against the time, so
//! the view is refused with the UI's existing 503 rather than any grant being
//! guessed active or expired; on a readable clock it reads as it always did.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::Value;
use tower::ServiceExt;

use super::tests::test_router_app_state_with_auth_and_key_server;
use super::{AppState, create_router};
use crate::config::AuthConfig;
use crate::identity_grants::{
    GrantAgent, GrantScope, GrantSubject, IdentityGrant, LocalIdentityGrantStore,
};

const BEARER: &str = "t16-static-bearer";

fn grant(id: &str) -> IdentityGrant {
    IdentityGrant {
        grant_id: id.to_string(),
        subject: GrantSubject::new("api_key".to_string(), "alice".to_string(), None),
        agent: GrantAgent::Any,
        capability: "cap".to_string(),
        tool: None,
        scope: GrantScope::Read,
        owner: None,
        expires_at: None,
        revoked_at: None,
        provenance: "p".to_string(),
        reason: "r".to_string(),
    }
}

/// Three grants: expiring (2099), revoked, and with no expiry.
async fn state_with_grants() -> (Arc<AppState>, tempfile::TempDir) {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER.to_string()),
        ..AuthConfig::default()
    };
    let (state, dir) = test_router_app_state_with_auth_and_key_server(&auth, None).await;
    let mut expiring = grant("g-expiring");
    expiring.expires_at = Some("2099-01-01T00:00:00Z".parse().unwrap());
    let mut revoked = grant("g-revoked");
    revoked.revoked_at = Some("2001-01-01T00:00:00Z".parse().unwrap());
    let (live, epoch) = state.meta_mcp.identity_grant_sink();
    crate::gateway::meta_mcp::publish_identity_grants(
        &live,
        &epoch,
        LocalIdentityGrantStore::from_grants(vec![expiring, revoked, grant("g-open")]),
    );
    (state, dir)
}

/// Every object in `value` that names grant `id`.
fn find_grant<'a>(value: &'a Value, id: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) if map.get("grant_id").and_then(Value::as_str) == Some(id) => {
            Some(value)
        }
        Value::Object(map) => map.values().find_map(|v| find_grant(v, id)),
        Value::Array(items) => items.iter().find_map(|v| find_grant(v, id)),
        _ => None,
    }
}

async fn fetch(state: &Arc<AppState>) -> (StatusCode, Value) {
    let request = Request::builder()
        .uri("/ui/api/control-plane")
        .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_344))))
        .body(Body::empty())
        .unwrap();
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).expect("a JSON body"))
}

async fn statuses(state: &Arc<AppState>) -> [String; 3] {
    let (status, body) = fetch(state).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    ["g-expiring", "g-revoked", "g-open"].map(|id| {
        find_grant(&body, id)
            .and_then(|g| g["status"].as_str())
            .unwrap_or_else(|| panic!("{id} is in the snapshot: {body}"))
            .to_owned()
    })
}

/// MIK-8202 ADVISORY (display) rule, P2 row 17: on a clock before 1970 the
/// grant view is refused with the existing 503 and a clock message; no grant
/// is shown, so none is guessed active or expired. Mutant: serve the view on a
/// guessed time.
#[tokio::test]
async fn t16_the_grant_view_on_an_unreadable_clock_is_refused_not_guessed() {
    let (state, _dir) = state_with_grants().await;
    let clock = crate::clock::test_clock::before_epoch();
    let (status, body) = fetch(&state).await;
    drop(clock);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(
        body["error"].as_str().is_some_and(|e| e.contains("clock")),
        "{body}"
    );
    assert!(find_grant(&body, "g-expiring").is_none(), "{body}");
}

/// T16 control: on a readable clock the same grants read as before.
#[tokio::test]
async fn t16_control_a_readable_clock_projects_the_grants_unchanged() {
    let (state, _dir) = state_with_grants().await;
    let [expiring, revoked, open] = statuses(&state).await;
    assert_eq!(
        (expiring.as_str(), revoked.as_str(), open.as_str()),
        ("approved", "revoked", "approved")
    );
}
