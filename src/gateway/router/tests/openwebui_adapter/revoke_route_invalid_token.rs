// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A token the provider already considers invalid is revoked (RFC 7009 §2.2).
//!
//! Google revokes every access token derived from a refresh token when that
//! refresh token is revoked, and answers the follow-up access-token request
//! 400 `{"error":"invalid_token"}` (observed live against Google, MIK-6745).
//! Only that exact pair counts; every other 400 stays `failed`, and the
//! refresh request answers 200 in those rows so the access answer alone
//! decides the outcome.

use super::*;

async fn delete_with(access: (u16, &str)) -> Value {
    let gw = gateway(true, &[(key("alice"), grant("alice"), Seed::Connected)]).await;
    gw.fixture.answer_hint("refresh_token", 200, "");
    gw.fixture.answer_hint("access_token", access.0, access.1);
    let (status, body) = delete(&gw, Some("alice"), ACCOUNT).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(gw.fixture.received(), both(), "both tokens, refresh first");
    assert_eq!(gw.fixture.state(&key("alice")).await, "revoked");
    body
}

/// The live Google case: refresh revoked, access already dead with it.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_route_access_already_invalid_after_refresh_is_confirmed() {
    let body = delete_with((400, r#"{"error":"invalid_token"}"#)).await;
    assert_eq!(body, revoked_body("confirmed"));
}

/// The refresh token itself already invalid, the access token revoked.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_route_refresh_already_invalid_is_confirmed() {
    let gw = gateway(true, &[(key("alice"), grant("alice"), Seed::Connected)]).await;
    gw.fixture
        .answer_hint("refresh_token", 400, r#"{"error":"invalid_token"}"#);
    gw.fixture.answer_hint("access_token", 200, "");
    let (status, body) = delete(&gw, Some("alice"), ACCOUNT).await;
    assert_eq!((status, body), (StatusCode::OK, revoked_body("confirmed")));
    assert_eq!(gw.fixture.received(), both());
}

/// A 400 naming any other error is a refusal, not a revoked token.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_route_other_400_error_codes_stay_failed() {
    for code in [
        "invalid_request",
        "invalid_client",
        "unsupported_token_type",
    ] {
        let body = delete_with((400, format!(r#"{{"error":"{code}"}}"#).as_str())).await;
        assert_eq!(body, revoked_body("failed"), "{code}");
    }
}

/// A 400 whose body names no error code cannot show the token is dead.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_route_400_without_an_error_code_stays_failed() {
    for raw in ["", "invalid_token", "<html>Bad Request</html>", "{}"] {
        let body = delete_with((400, raw)).await;
        assert_eq!(body, revoked_body("failed"), "{raw:?}");
    }
}
