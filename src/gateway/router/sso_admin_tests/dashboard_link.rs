// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E5-T7 (MIK-7570.SESSION.1): minting a dashboard link takes a credential
//! that redemption also accepts. An SSO admin is an admin everywhere else, but
//! redemption needs a static admin credential, so a link it minted would be
//! dead on arrival.

use super::*;

#[tokio::test]
async fn an_sso_admin_may_not_mint_a_dashboard_link() {
    let gw = gateway(&[ADMIN_GROUP_RULE]).await;
    let alice = gw.a.token("alice", &["ops-admins"], &json!({}));
    assert_eq!(
        standing(&gw.state, &alice).await,
        Standing::Admin,
        "alice is an SSO admin, so the refusal below is about the credential"
    );
    let before = gw.state.dashboard_bootstrap.peek();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/ui/api/dashboard-link")
        .header("authorization", format!("Bearer {alice}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, body) = send(&gw.state, request).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        gw.state.dashboard_bootstrap.peek(),
        before,
        "nothing re-armed"
    );
}
