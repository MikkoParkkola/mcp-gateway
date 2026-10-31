// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A sign-in confirmed on another client of the same backend reaches the
//! serving client before its next send, even while the serving client still
//! holds a live token. The serving client is driven through the transport's
//! own request path (`get_oauth_token`), as a call would drive it.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::HttpTransport;
use crate::oauth::client::authorize_tests::{client, token_endpoint};
use crate::oauth::client::sign_in::{PendingGrant, SignIn, SignInStatus};
use crate::oauth::{OAuthClient, TokenInfo};
use crate::test_wait::HANG_BOUND;

fn a_token(access: &str, refresh: Option<&str>, expires_in: u64) -> TokenInfo {
    TokenInfo::from_response(
        access.to_owned(),
        None,
        refresh.map(str::to_owned),
        Some(expires_in),
        None,
    )
}

/// A serving client and a confirming client of one backend: the same store,
/// the same issuer, the same status cell. The serving client holds `old`.
struct Pair {
    serving: Arc<HttpTransport>,
    confirming: OAuthClient,
    _dir: tempfile::TempDir,
}

async fn pair(old: &TokenInfo) -> Pair {
    let dir = tempfile::tempdir().unwrap();
    let (issuer, _forms) = token_endpoint(Some("access-b")).await;
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let serving = client(dir.path(), Some(&issuer))
        .with_sign_in_status(Arc::clone(&cell))
        .with_open_browser(Arc::new(|_: &str| true));
    serving.seed_token_for_test(old);
    let confirming = client(dir.path(), Some(&issuer)).with_sign_in_status(cell);
    let transport = HttpTransport::new_with_oauth(
        "http://127.0.0.1:9/mcp",
        HashMap::new(),
        Duration::from_secs(5),
        true,
        Some(serving),
        None,
    )
    .unwrap();
    Pair {
        serving: transport,
        confirming,
        _dir: dir,
    }
}

async fn confirm(pair: &Pair, token: TokenInfo) {
    let grant = PendingGrant::from_token(token);
    let cancel = tokio_util::sync::CancellationToken::new();
    let by = tokio::time::Instant::now() + HANG_BOUND;
    pair.confirming
        .save_confirmed(grant, &cancel, by)
        .await
        .expect("the confirm saves");
}

async fn next_token(pair: &Pair) -> String {
    tokio::time::timeout(HANG_BOUND, pair.serving.get_oauth_token())
        .await
        .expect("the request path answers (no new sign-in is waited on)")
        .expect("a token")
        .expect("oauth is configured")
}

// A re-sign-in while the serving client holds a live token: its next send
// uses the confirmed token. Red today: the fast path returns the cache.
#[tokio::test]
async fn a_confirmed_sign_in_replaces_a_live_token_in_the_serving_client() {
    let pair = pair(&a_token("old", None, 3600)).await;
    assert_eq!(next_token(&pair).await, "old");

    confirm(&pair, a_token("new", Some("r2"), 3600)).await;

    assert_eq!(next_token(&pair).await, "new");
    assert_eq!(
        next_token(&pair).await,
        "new",
        "back on the cached fast path"
    );
}

// The confirmed token is already inside the 60 s expiry buffer and the old
// cache had no refresh token: the serving client refreshes with the stored
// refresh token and does not ask for another sign-in. Red today: the live old
// token is returned.
#[tokio::test]
async fn a_confirmed_refreshable_token_inside_the_expiry_buffer_is_refreshed_not_re_signed() {
    let pair = pair(&a_token("old", None, 3600)).await;
    assert_eq!(next_token(&pair).await, "old");

    confirm(&pair, a_token("short", Some("r2"), 30)).await;

    assert_eq!(next_token(&pair).await, "access-b");
}

// `get_token`'s unexpired-cache return makes the same check.
#[tokio::test]
async fn get_token_s_cached_return_sees_a_confirmed_sign_in() {
    let pair = pair(&a_token("old", None, 3600)).await;
    let serving = pair.serving.oauth_client_for_test().expect("a client");
    assert_eq!(serving.lock().await.get_token().await.unwrap(), "old");

    confirm(&pair, a_token("new", Some("r2"), 3600)).await;

    assert_eq!(serving.lock().await.get_token().await.unwrap(), "new");
}
