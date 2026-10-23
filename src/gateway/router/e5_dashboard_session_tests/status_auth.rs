// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8786.AUTH.1 / AUTH.5: `/ui/api/status` states the auth facts the page
//! decides from (`auth: {enabled, signed_in, admin}`), in both views, for
//! every caller kind. Through `create_router`, so the real `auth_middleware`
//! chooses the caller.

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::{
    ADMIN_KEY, STANDARD_KEY, STATUS, fixture, fixture_with, get, is_admin_view, issue, request,
    send,
};
use crate::config::AuthConfig;

/// The status answer's `auth` member.
fn auth_facts(reply: &super::Reply) -> Value {
    reply.json().get("auth").cloned().unwrap_or(Value::Null)
}

/// The redacted view: counts, no server inventory (AUTH.5).
fn assert_redacted(row: &str, reply: &super::Reply) {
    assert!(
        reply.json().get("servers").is_none(),
        "{row}: a non-admin caller got the server inventory: {}",
        reply.body
    );
}

/// S1 (D2): auth on, signed in through the dashboard link. The session cookie
/// alone makes the caller an admin, so the page must be told it is signed in,
/// never that authentication is off.
#[tokio::test]
async fn s1_a_dashboard_session_is_stated_as_a_signed_in_admin() {
    let (state, _dir) = fixture().await;
    let handle = issue(&state);
    let reply = send(&state, get(STATUS, Some(&handle))).await;
    assert!(
        is_admin_view(&reply),
        "S1: the session sees the full view: {}",
        reply.body
    );
    assert_eq!(
        auth_facts(&reply),
        json!({"enabled": true, "signed_in": true, "admin": true}),
        "S1: {}",
        reply.body
    );
}

/// S2 (D3): auth on with a public path covering the status route. The anonymous
/// caller gets the redacted view, stated as signed out on a secured gateway.
#[tokio::test]
async fn s2_an_anonymous_caller_on_a_public_status_path_is_stated_as_signed_out() {
    let (state, _dir) = fixture_with(&["/health", STATUS]).await;
    let reply = send(&state, get(STATUS, None)).await;
    assert_eq!(reply.status, StatusCode::OK, "S2: {}", reply.body);
    assert_redacted("S2", &reply);
    assert_eq!(
        auth_facts(&reply),
        json!({"enabled": true, "signed_in": false, "admin": false}),
        "S2: {}",
        reply.body
    );
}

/// S3 (D1): auth off. The anonymous caller is not an admin by design, and the
/// page must be told authentication is off.
#[tokio::test]
async fn s3_auth_off_is_stated_as_off() {
    let (state, _dir) =
        super::test_router_app_state_with_auth_and_key_server(&AuthConfig::default(), None).await;
    let reply = send(&state, get(STATUS, None)).await;
    assert_eq!(reply.status, StatusCode::OK, "S3: {}", reply.body);
    assert_redacted("S3", &reply);
    assert_eq!(
        auth_facts(&reply),
        json!({"enabled": false, "signed_in": false, "admin": false}),
        "S3: {}",
        reply.body
    );
}

/// S4: auth on, an admin API key.
#[tokio::test]
async fn s4_an_admin_key_is_stated_as_a_signed_in_admin() {
    let (state, _dir) = fixture().await;
    let reply = send(&state, request("GET", STATUS, None, Some(ADMIN_KEY), false)).await;
    assert!(is_admin_view(&reply), "S4: {}", reply.body);
    assert_eq!(
        auth_facts(&reply),
        json!({"enabled": true, "signed_in": true, "admin": true}),
        "S4: {}",
        reply.body
    );
}

/// S5: auth on, a key without the admin role: signed in, not an admin, and
/// still the redacted view.
#[tokio::test]
async fn s5_a_standard_key_is_stated_as_signed_in_without_admin() {
    let (state, _dir) = fixture().await;
    let reply = send(
        &state,
        request("GET", STATUS, None, Some(STANDARD_KEY), false),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "S5: {}", reply.body);
    assert_redacted("S5", &reply);
    assert_eq!(
        auth_facts(&reply),
        json!({"enabled": true, "signed_in": true, "admin": false}),
        "S5: {}",
        reply.body
    );
}

/// S6 (control): auth on with the default public paths, anonymous: refused
/// before the route, unchanged by MIK-8786.
#[tokio::test]
async fn s6_an_anonymous_caller_is_refused_when_status_is_not_public() {
    let (state, _dir) = fixture().await;
    let reply = send(&state, get(STATUS, None)).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "S6: {}", reply.body);
}
