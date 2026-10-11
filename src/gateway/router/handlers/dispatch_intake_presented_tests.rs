// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `intake` takes the request's headers off it rather than copying them, so
//! the credential capture must run before the take. A capture moved after it
//! would hash an empty header map: no bearer or session binding, silently.

use axum::body::Body;
use axum::http::Request;

use super::intake;
use crate::gateway::auth::SESSION_COOKIE;
use crate::gateway::router::tests::test_router_app_state;
use crate::hashing::sha256_hex;

/// A `/mcp` request presenting a bearer and a dashboard session cookie keeps
/// both digests through `intake`. Mutant: the take moved above
/// `Presented::capture` (both digests become `None`).
#[tokio::test]
async fn intake_keeps_the_presented_bearer_and_session_digests() {
    let (state, _store) = test_router_app_state().await;
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", "Bearer intake-row-token")
        .header("cookie", format!("{SESSION_COOKIE}=intake-row-handle"))
        .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
        .unwrap();
    let Ok((_, _, admitted)) = intake(&state, request).await else {
        panic!("intake refused the request");
    };
    let (session, bearer) = admitted.presented.digests_for_test();
    let expected_bearer = sha256_hex(b"intake-row-token");
    let expected_session = sha256_hex(b"intake-row-handle");
    assert_eq!(
        bearer,
        Some(expected_bearer.as_str()),
        "the bearer digest survived the header take"
    );
    assert_eq!(
        session,
        Some(expected_session.as_str()),
        "the session digest survived the header take"
    );
}
