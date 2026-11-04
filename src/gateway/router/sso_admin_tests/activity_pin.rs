// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Activity answers an admin caller before it reads the role mapping, so the
//! admin flag a key-server caller is authenticated with decides whether it
//! reads other principals' calls. That flag follows the pinned mapping: a
//! caller the pinned mapping leaves unmapped is refused even when a reload
//! after the pin maps it to Admin.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::http::StatusCode;
use serde_json::json;
use tower::ServiceExt;

use super::{ADMIN_GROUP_RULE, gateway, set_rules};
use crate::gateway::meta_mcp::visible::seams;
use crate::gateway::routes;

const GRANTS: &[&str] = &[ADMIN_GROUP_RULE];
const NONE: &[&str] = &[];

/// The Activity list for `bearer`, with `pinned` pinned and `live` published
/// after the pin: its status and body.
async fn activity(
    state: &Arc<super::AppState>,
    bearer: &str,
    pinned: &'static [&'static str],
    live: &'static [&'static str],
) -> (StatusCode, String) {
    set_rules(state, pinned);
    let later = Arc::clone(state);
    seams::after_pin(move || set_rules(&later, live));
    let request = axum::http::Request::get(format!("{}?server=srv", routes::UI_ACTIVITY))
        .header("authorization", format!("Bearer {bearer}"))
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_345))))
        .body(axum::body::Body::empty())
        .expect("a request");
    let response = super::create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("a response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn activity_follows_the_pinned_admin_flag() {
    let mut gw = gateway(GRANTS).await;
    let _log = super::super::ui_access_matrix_tests::seed_log(&mut gw.state);
    let token = gw.a.token("alice", &["ops-admins"], &json!({}));
    // The seeded call by another principal is the second entry's tool.
    let other = "tool_1";

    let (status, body) = activity(&gw.state, &token, GRANTS, GRANTS).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "premise: admin reads Activity: {body}"
    );
    assert!(
        body.contains(other),
        "premise: admin sees another principal: {body}"
    );
    let (status, body) = activity(&gw.state, &token, NONE, NONE).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "premise: unmapped is refused: {body}"
    );

    let (status, body) = activity(&gw.state, &token, NONE, GRANTS).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "pinned unmapped, current Admin: judged by the current mapping: {body}"
    );
    assert!(
        !body.contains(other),
        "another principal's call leaked: {body}"
    );
}
