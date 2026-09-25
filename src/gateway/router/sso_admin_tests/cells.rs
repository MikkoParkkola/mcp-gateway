// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The E1-core cells. Fixture and helpers are in the parent module.

use super::*;

/// The `/auth/token` exchange: an ID token in, an opaque key-server token out.
async fn exchange(state: &Arc<AppState>, id_token: &str) -> String {
    let body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token={id_token}"
    );
    let request = axum::http::Request::post("/auth/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let (status, body) = send(state, request).await;
    assert_eq!(status, StatusCode::OK, "exchange: {body}");
    body["access_token"]
        .as_str()
        .expect("an access token")
        .to_string()
}

/// E1-T1: a delegated bearer in the rule's group is an admin: the admin
/// meta-tool answers and the admin tools are listed.
#[tokio::test]
async fn sso_group_admin_can_call_admin_meta_tool() {
    let gw = gateway(&[ADMIN_GROUP_RULE]).await;
    let token = gw.a.token("alice", &["ops-admins"], &json!({}));
    assert_eq!(standing(&gw.state, &token).await, Standing::Admin);
}

/// E1-T2: the same caller passes the admin UI's gate. With no reload context
/// the handler answers 503 past the gate, so reaching it is observable; a
/// caller outside the group stops at the gate with 403.
#[cfg(feature = "webui")]
#[tokio::test]
async fn sso_admin_reaches_ui_admin_route() {
    let gw = gateway(&[ADMIN_GROUP_RULE]).await;
    let reload = |token: &str| {
        axum::http::Request::post("/ui/api/reload")
            .header("authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap()
    };
    let admin = gw.a.token("alice", &["ops-admins"], &json!({}));
    let (status, body) = send(&gw.state, reload(&admin)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(
        body.to_string().contains("Config reload is not enabled"),
        "the handler ran past the admin gate: {body}"
    );

    let staff = gw.a.token("bob", &[], &json!({}));
    let (status, body) = send(&gw.state, reload(&staff)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

/// E1-T3: the same identity through the `/auth/token` exchange is an admin
/// with the opaque token too.
#[tokio::test]
async fn sso_admin_via_exchanged_token() {
    let gw = gateway(&[ADMIN_GROUP_RULE]).await;
    let opaque = exchange(&gw.state, &gw.a.token("alice", &["ops-admins"], &json!({}))).await;
    assert_eq!(standing(&gw.state, &opaque).await, Standing::Admin);
}

/// E1-T4 (positive control): an SSO caller outside the admin group is
/// authenticated and standard. Guards against admin for every OIDC caller.
#[tokio::test]
async fn sso_non_admin_group_is_standard() {
    let gw = gateway(&[ADMIN_GROUP_RULE]).await;
    let token = gw.a.token("bob", &["devs"], &json!({}));
    assert_eq!(standing(&gw.state, &token).await, Standing::Standard);
}

/// E1-T5: the same group name from issuer B is standard. The key server
/// admits B, so the caller is authenticated and only the admin rule is
/// scoped away.
#[tokio::test]
async fn admin_rule_for_issuer_a_ignores_issuer_b() {
    let gw = gateway(&[ADMIN_GROUP_RULE]).await;
    let token = gw.b.token("alice", &["ops-admins"], &json!({}));
    assert_eq!(standing(&gw.state, &token).await, Standing::Standard);
}

/// E1-T6: a reload that removes the rule revokes admin on the next request,
/// for the delegated bearer and for a token exchanged before the reload.
#[tokio::test]
async fn reload_removing_admin_rule_revokes_next_request() {
    let gw = gateway(&[ADMIN_GROUP_RULE]).await;
    let token = gw.a.token("alice", &["ops-admins"], &json!({}));
    let opaque = exchange(&gw.state, &token).await;
    assert_eq!(standing(&gw.state, &token).await, Standing::Admin);
    assert_eq!(standing(&gw.state, &opaque).await, Standing::Admin);

    set_rules(&gw.state, &[]);
    assert_eq!(standing(&gw.state, &token).await, Standing::Standard);
    assert_eq!(standing(&gw.state, &opaque).await, Standing::Standard);

    // And the other direction: restoring the rule grants it again, same tokens.
    set_rules(&gw.state, &[ADMIN_GROUP_RULE]);
    assert_eq!(standing(&gw.state, &opaque).await, Standing::Admin);
}

/// E1-T6b: listener re-validation (`auth::live::current_client`) resolves
/// through the same function as the middleware, so it grants admin from the
/// rule and loses it on the reload.
#[tokio::test]
async fn revalidated_client_follows_the_live_rule() {
    let gw = gateway(&[ADMIN_GROUP_RULE]).await;
    let token = gw.a.token("alice", &["ops-admins"], &json!({}));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    let held = crate::gateway::auth::live::held_credential(&headers);
    let authorizer = super::super::build_auth_state(&gw.state);
    let client = crate::gateway::auth::live::current_client(&authorizer, held.as_ref())
        .await
        .expect("the credential validates");
    assert!(client.admin, "the rule grants admin on re-validation");

    set_rules(&gw.state, &[]);
    let client = crate::gateway::auth::live::current_client(&authorizer, held.as_ref())
        .await
        .expect("the credential still validates");
    assert!(!client.admin, "the reload revoked it");
}

/// E1-T8: an email rule is not satisfied by an unverified email (A9 D1). The
/// control shows the same token with a verified email is an admin.
#[tokio::test]
async fn unverified_email_rule_confers_no_admin() {
    let rule = "{ issuer: \"https://idp-a.example\", email: boss@corp.com, role: admin }";
    let gw = gateway(&[rule]).await;
    let claims = |verified: bool| json!({"email": "boss@corp.com", "email_verified": verified});
    let unverified = gw.a.token("boss", &[], &claims(false));
    assert_eq!(standing(&gw.state, &unverified).await, Standing::Standard);
    let verified = gw.a.token("boss", &[], &claims(true));
    assert_eq!(standing(&gw.state, &verified).await, Standing::Admin);
}

/// E1-T9: a trusted-proxy header naming the admin's `(issuer, sub)` confers
/// nothing. The header is live (it resolves to that grant subject), but a
/// header identity is never a `VerifiedIdentity`, so it cannot be admin.
#[tokio::test]
async fn header_identity_is_never_admin() {
    use crate::security::caller_identity::{CallerIdentityConfig, CallerIdentityMode};
    let mut gw = gateway(&[ADMIN_GROUP_RULE]).await;
    let proxy: std::net::SocketAddr = "10.0.0.5:40000".parse().unwrap();
    let caller_identity = CallerIdentityConfig {
        mode: CallerIdentityMode::TrustedProxy,
        trusted_proxies: vec![proxy.ip()],
        authority: ISS_A.to_string(),
        ..CallerIdentityConfig::default()
    };
    let state = Arc::get_mut(&mut gw.state).expect("sole owner");
    state.meta_mcp = Arc::new(
        crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&state.backends))
            .with_caller_identity(caller_identity.clone()),
    );

    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-gateway-identity-subject", "alice".parse().unwrap());
    let subject = super::super::identity::caller_grant_subject(
        None,
        &headers,
        Some(proxy),
        &caller_identity,
        None,
        None,
        None,
    )
    .await
    .expect("the trusted proxy's header is honoured")
    .expect("it names a subject");
    assert_eq!(
        (subject.authority.as_str(), subject.subject.as_str()),
        (ISS_A, "alice")
    );

    let via_proxy = |mut request: axum::http::Request<axum::body::Body>| {
        request
            .headers_mut()
            .insert("x-gateway-identity-subject", "alice".parse().unwrap());
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(proxy));
        request
    };
    assert_eq!(
        standing_of(&gw.state, STANDARD_KEY, via_proxy).await,
        Standing::Standard
    );
}

/// E1-T11 (positive control): static admin stays the break-glass path.
#[tokio::test]
async fn static_admin_key_still_admin() {
    let gw = gateway(&[]).await;
    assert_eq!(standing(&gw.state, ADMIN_KEY).await, Standing::Admin);
    assert_eq!(standing(&gw.state, BEARER).await, Standing::Admin);
    assert_eq!(standing(&gw.state, STANDARD_KEY).await, Standing::Standard);
}
