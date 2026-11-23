// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A server whose name has a space or a non-ASCII letter still loads (the load check's own row), and its direct route
//! reaches it when the caller percent-encodes the name: the name rule refuses only control characters and `.`/`..`.

use std::sync::atomic::Ordering;

use axum::http::StatusCode;
use serde_json::json;

use super::direct_guards_fixture::{Answer, fixture, post_direct, replace_backend};

/// NAME.3: `POST /mcp/my%20server` and `POST /mcp/p%C3%A4iv%C3%A4` each reach their own backend exactly once.
#[tokio::test]
async fn a_name_with_a_space_or_a_non_ascii_letter_answers_on_its_encoded_direct_route() {
    for (name, encoded) in [("my server", "my%20server"), ("päivä", "p%C3%A4iv%C3%A4")] {
        let fx = fixture(Answer::Ok, |_| {}).await;
        let calls = replace_backend(&fx, name);
        let (status, body) =
            post_direct(&fx, encoded, "k-std", "read", json!({}), None, None).await;
        assert_eq!(status, StatusCode::OK, "{name:?}: {body}");
        assert!(body.get("error").is_none(), "{name:?}: {body}");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "{name:?}: the call did not reach the backend named by the decoded path"
        );
    }
}
