// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A key-server caller's admin flag is judged by the role mapping of the
//! generation the router pinned on the request, not by one a reload
//! published after the pin.
//!
//! Each request publishes the pinned mapping, then a hook armed for the next
//! pin publishes the other one, so authentication runs with one generation
//! pinned and another current. The answer must equal the one under the pinned
//! mapping alone, both ways round: a judge that reads the current generation
//! fails one direction, one that admits on either fails the other. Both the
//! protected branch and the public-path branch of authentication are driven,
//! as each calls the key server on its own.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::StatusCode;
use serde_json::json;
use tower::ServiceExt;

use super::{ADMIN_GROUP_RULE, Gateway, Standing, gateway, set_rules, standing_of};
use crate::gateway::meta_mcp::visible::seams;

/// `rules` as a reload would publish them, from a hook that owns its inputs.
fn publish_later(gw: &Gateway, rules: &'static [&'static str]) {
    let state = Arc::clone(&gw.state);
    seams::after_pin(move || set_rules(&state, rules));
}

/// `bearer`'s standing with `pinned` pinned on each request and `live`
/// published after the pin, before authentication.
async fn standing_across(
    gw: &Gateway,
    bearer: &str,
    pinned: &'static [&'static str],
    live: &'static [&'static str],
) -> Standing {
    standing_of(&gw.state, bearer, |request| {
        set_rules(&gw.state, pinned);
        publish_later(gw, live);
        request
    })
    .await
}

const GRANTS: &[&str] = &[ADMIN_GROUP_RULE];
const NONE: &[&str] = &[];

/// Forward and reverse on one gateway, with its premise: the two mappings
/// answer differently when nothing reloads.
async fn follows_the_pin(gw: &Gateway) {
    let token = gw.a.token("alice", &["ops-admins"], &json!({}));
    assert_eq!(
        standing_across(gw, &token, GRANTS, GRANTS).await,
        Standing::Admin,
        "premise: the rule grants admin"
    );
    assert_eq!(
        standing_across(gw, &token, NONE, NONE).await,
        Standing::Standard,
        "premise: without the rule, no admin"
    );
    assert_eq!(
        standing_across(gw, &token, GRANTS, NONE).await,
        Standing::Admin,
        "pinned grants, current does not: judged by the current mapping"
    );
    assert_eq!(
        standing_across(gw, &token, NONE, GRANTS).await,
        Standing::Standard,
        "pinned does not grant, current does: judged by the current mapping"
    );
}

#[tokio::test]
async fn the_admin_flag_follows_the_pinned_mapping() {
    follows_the_pin(&gateway(GRANTS).await).await;
}

/// The same on a public `/mcp`, where a presented credential is still
/// authenticated, through the public-path branch's own key-server call.
#[tokio::test]
async fn the_admin_flag_follows_the_pinned_mapping_on_a_public_path() {
    let gw = super::gateway_with_public(GRANTS, &["/mcp"]).await;
    assert!(
        gw.state
            .live_config
            .generation()
            .auth()
            .is_public_path("/mcp"),
        "premise: /mcp is public"
    );
    follows_the_pin(&gw).await;
}

/// The handler-less refusal: `request` through authentication alone, with
/// no generation pinned, answers the no-pin error and never runs the handler.
async fn refused_unpinned(gw: &Gateway, request: axum::http::Request<axum::body::Body>) {
    let ran = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&ran);
    let app = axum::Router::new()
        .route(
            "/mcp",
            axum::routing::post(move || async move {
                seen.store(true, Ordering::SeqCst);
                "reached"
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            super::super::build_auth_state(&gw.state),
            crate::gateway::auth::auth_middleware,
        ));
    let response = app.oneshot(request).await.expect("a response");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    assert!(
        String::from_utf8_lossy(&body).contains(crate::gateway::router::UNPINNED),
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert!(!ran.load(Ordering::SeqCst), "the handler ran unpinned");
}

/// A live dashboard session is accepted before a credential is read, so the
/// session path refuses an unpinned request on its own, never judging the
/// session by the current key table.
#[tokio::test]
async fn an_unpinned_dashboard_session_never_reaches_a_handler() {
    use crate::gateway::auth::{Now, SESSION_COOKIE, SessionLimits};
    let gw = gateway(GRANTS).await;
    let limits = SessionLimits::from(&gw.state.live_config.get().auth.dashboard_session);
    let handle = gw
        .state
        .dashboard_bootstrap
        .issue_session_at(Now::read(), &limits);
    let request = axum::http::Request::post("/mcp")
        .header(
            axum::http::header::COOKIE,
            format!("{SESSION_COOKIE}={handle}"),
        )
        .header("content-type", "application/json")
        .body(axum::body::Body::from("{}"))
        .expect("a request");
    refused_unpinned(&gw, request).await;
}

/// Authentication with no generation pinned refuses the request, never
/// judging it by the current one: the handler behind it never runs.
#[tokio::test]
async fn an_unpinned_request_never_reaches_a_handler() {
    let gw = gateway(GRANTS).await;
    let token = gw.a.token("alice", &["ops-admins"], &json!({}));
    refused_unpinned(&gw, super::rpc(&token, "tools/list", &json!({}))).await;
}
