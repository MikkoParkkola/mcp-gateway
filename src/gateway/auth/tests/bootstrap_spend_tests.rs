// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1529 item 5: a dashboard link presented from elsewhere dies on first use.
//!
//! The link lives in a URL, so it can outlive the gateway's own logs in a
//! browser history, a proxy log or a `Referer`. A refusal that left the value
//! live let whoever held it keep trying.

use axum::http::StatusCode;

use super::*;

fn redeem_from(state: &AuthState, value: &str, peer: [u8; 4], forwarded: bool) -> StatusCode {
    redeem_body(state, value, peer, forwarded).0
}

fn redeem_body(
    state: &AuthState,
    value: &str,
    peer: [u8; 4],
    forwarded: bool,
) -> (StatusCode, String) {
    let mut request = Request::builder()
        .uri(format!("/dashboard?bootstrap={value}"))
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            peer, 12345,
        ))));
    if forwarded {
        request = request.header("x-forwarded-for", "203.0.113.9");
    }
    let request = request.body(Body::empty()).expect("request builds");
    let response =
        try_dashboard_bootstrap(state, &request).expect("a bootstrap link is always answered here");
    let status = response.status();
    let body = futures::executor::block_on(axum::body::to_bytes(response.into_body(), usize::MAX))
        .expect("body");
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// T5d: the refusal says whether the link was used up.
#[test]
fn t5d_the_refusal_says_whether_the_link_is_spent() {
    let (state, printed) = bootstrap_state(Some("bearer"), vec![]);
    let (_, wrong) = redeem_body(&state, "not-the-value", REMOTE, false);
    assert!(!wrong.contains("used it up"), "{wrong}");
    let (_, spent) = redeem_body(&state, &printed, REMOTE, false);
    assert!(spent.contains("used it up"), "{spent}");
}

const LOCAL: [u8; 4] = [127, 0, 0, 1];
const REMOTE: [u8; 4] = [198, 51, 100, 7];

/// T5: a non-local attempt with the real value spends it.
#[test]
fn t5_a_non_local_redemption_spends_the_link() {
    for (peer, forwarded) in [(REMOTE, false), (LOCAL, true)] {
        let (state, printed) = bootstrap_state(Some("bearer"), vec![]);
        assert_eq!(
            redeem_from(&state, &printed, peer, forwarded),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            redeem_from(&state, &printed, LOCAL, false),
            StatusCode::UNAUTHORIZED,
            "the link must be dead after a refused non-local attempt ({peer:?}, forwarded={forwarded})"
        );
    }
}

/// T5b: the spend is match-only; a wrong value spends nothing.
#[test]
fn t5b_a_wrong_non_local_value_spends_nothing() {
    let (state, printed) = bootstrap_state(Some("bearer"), vec![]);
    assert_eq!(
        redeem_from(&state, "not-the-value", REMOTE, false),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        redeem_from(&state, &printed, LOCAL, false),
        StatusCode::SEE_OTHER
    );
}

/// T5c: with no admin credential, a local refusal keeps the value (the
/// operator fixes the config and retries), a non-local one spends it.
#[test]
fn t5c_no_credential_keeps_the_link_only_for_the_local_operator() {
    let (state, printed) = bootstrap_state(None, vec![]);
    assert_eq!(
        redeem_from(&state, &printed, LOCAL, false),
        StatusCode::UNAUTHORIZED
    );
    assert!(
        state.dashboard_bootstrap.peek().is_some(),
        "a local refusal kept it"
    );
    assert_eq!(
        redeem_from(&state, &printed, REMOTE, false),
        StatusCode::UNAUTHORIZED
    );
    assert!(
        state.dashboard_bootstrap.peek().is_none(),
        "a non-local refusal spent it"
    );
}
