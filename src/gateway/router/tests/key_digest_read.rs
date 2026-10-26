// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The UI config read never carries a configured key's digest, current or
//! previous (ADR-022): a digest is all an offline guess needs.
use super::*;
use pretty_assertions::assert_eq;

#[tokio::test]
async fn ui_config_read_shows_no_key_digest() {
    let mut auth = scoped_auth_config(true);
    let previous = crate::config::api_key_digest_spec("previous-scoped-key".as_bytes());
    let key = &mut auth.api_keys[0];
    key.previous_key_sha256 = Some(previous.clone());
    let grace_end =
        chrono::DateTime::parse_from_rfc3339("2999-01-01T00:00:00Z").expect("an instant");
    key.previous_expires_at = Some(grace_end.with_timezone(&chrono::Utc));
    let current = key
        .key_sha256
        .clone()
        .expect("the fixture key has a digest");
    let (state, _store) = test_router_app_state_with_auth(&auth).await;

    let request = axum::http::Request::get("/ui/api/config")
        .header("authorization", "Bearer scoped-key")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = create_router(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8_lossy(&body);
    for digest in [&current, &previous] {
        let hex = digest.strip_prefix("sha256:").expect("a digest spec");
        assert!(
            !body.contains(hex),
            "a key digest reached the UI config read: {body}"
        );
    }
}
