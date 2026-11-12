// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A sign-in under another issuer confirmed while a login's code exchange is
//! held at the token server: nothing of the old issuer is handed back, through
//! either entry a login has. An issuer switch is confirmed only through the
//! web UI's sign-in, so the rows need it.
#![cfg(feature = "webui")]

use std::sync::Arc;

use super::*;

/// A code exchange already sent when a sign-in under another issuer is
/// confirmed: the login hands back no token, caches nothing of the old
/// issuer, and the new sign-in's status stands.
async fn a_switch_during_the_code_exchange_hands_back_nothing(entry: Entry, label: &str) {
    use super::sign_in::{SignIn, SignInStatus};
    use super::token_server_fixture::{Answer, TokenServer};
    let server = TokenServer::start(&[Answer::HoldThenRotate]).await;
    let dir = tempfile::tempdir().unwrap();
    let cell = Arc::new(SignInStatus::new(SignIn::NeverSignedIn));
    let mut login = client(dir.path(), Some(&server.base)).with_sign_in_status(Arc::clone(&cell));
    let switch = async {
        server.arrivals(1, crate::test_wait::HANG_BOUND).await;
        cell.record_install("cov3-backend-other-issuer");
        cell.set_held(Some(4_000_000_000), false);
        server.release.notify_one();
    };

    let ((outcome, _), ()) = tokio::join!(
        approve_via(&mut login, &server.base, entry, Browser::Opens),
        switch
    );

    assert_eq!(
        server.requests(),
        1,
        "{label}: the code exchange was in flight"
    );
    let refused = outcome.expect_err("no old-issuer token after the switch");
    assert!(
        matches!(refused, Error::AuthorizationRequired { .. }),
        "{label}: {refused}"
    );
    assert!(
        login.current_token.read().is_none(),
        "{label}: the old issuer's answer is not cached"
    );
    assert!(
        matches!(cell.snapshot(), SignIn::SignedIn { expires_at: Some(at) }
            if at == std::time::UNIX_EPOCH + std::time::Duration::from_secs(4_000_000_000)),
        "{label}: the new sign-in's status stands: {:?}",
        cell.snapshot()
    );
}

/// Through the token step a request takes (`get_token`).
#[tokio::test]
async fn a_switch_while_a_code_exchange_is_in_flight_hands_back_nothing() {
    a_switch_during_the_code_exchange_hands_back_nothing(Entry::GetToken, "get_token").await;
}

/// Through the public `authorize`, which has no token step around it.
#[tokio::test]
async fn a_switch_during_a_direct_authorize_hands_back_nothing() {
    a_switch_during_the_code_exchange_hands_back_nothing(Entry::Authorize, "authorize").await;
}
