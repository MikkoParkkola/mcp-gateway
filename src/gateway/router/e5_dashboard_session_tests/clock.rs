// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 AC11: the session middleware on a wall clock that reads before
//! 1970. A live session cannot be dated, so it is refused, but it is not
//! ended: the browser keeps its cookie, and the same session authenticates
//! once the clock reads again. A refusal must never destroy state.

use super::*;

/// The request on a clock before 1970, then the clock restored.
async fn before_epoch(state: &Arc<AppState>, request: Request<Body>) -> Reply {
    let _clock = crate::clock::test_clock::before_epoch();
    send(state, request).await
}

/// With only the session cookie, the request is refused (401) and the cookie
/// is kept; with a readable clock the same cookie authenticates.
#[tokio::test]
async fn a_live_session_on_a_clock_before_1970_is_refused_and_kept() {
    let (state, _dir) = fixture().await;
    let live = issue(&state);
    let out = before_epoch(&state, get(STATUS, Some(&live))).await;
    assert_eq!(out.status, StatusCode::UNAUTHORIZED, "{}", out.body);
    assert!(out.body.contains("1970"), "says why: {}", out.body);
    assert!(
        out.set_cookie().is_empty(),
        "the browser keeps its cookie: {}",
        out.set_cookie()
    );
    let later = send(&state, get(STATUS, Some(&live))).await;
    assert!(
        is_admin_view(&later),
        "once the clock reads, the same session authenticates: {} {}",
        later.status,
        later.body
    );
}

/// A bearer beside the cookie still authenticates on that clock, and the
/// cookie is not cleared on the way.
#[tokio::test]
async fn a_bearer_beside_a_session_on_a_clock_before_1970_keeps_the_cookie() {
    let (state, _dir) = fixture().await;
    let live = issue(&state);
    let out = before_epoch(
        &state,
        request("GET", STATUS, Some(&live), Some(BEARER), false),
    )
    .await;
    assert!(is_admin_view(&out), "{} {}", out.status, out.body);
    assert!(!out.clears_cookie(), "{}", out.set_cookie());
    assert!(is_admin_view(&send(&state, get(STATUS, Some(&live))).await));
}

/// A public path is served on that clock without clearing the cookie.
#[tokio::test]
async fn a_public_path_on_a_clock_before_1970_keeps_the_cookie() {
    let (state, _dir) = fixture_with(&["/health", STATUS]).await;
    let live = issue(&state);
    let out = before_epoch(&state, get(STATUS, Some(&live))).await;
    assert_eq!(out.status, StatusCode::OK, "{}", out.body);
    assert!(!out.clears_cookie(), "{}", out.set_cookie());
    assert!(is_admin_view(&send(&state, get(STATUS, Some(&live))).await));
}

/// A bootstrap link presented beside the session on that clock is refused
/// unspent: no session is issued on a time that cannot be dated, the live
/// session's cookie is kept, and the same link redeems once the clock reads.
/// Mutant: the link consumed whatever the clock.
#[tokio::test]
async fn a_bootstrap_link_on_a_clock_before_1970_keeps_the_session() {
    let (state, _dir) = fixture().await;
    let live = issue(&state);
    let value = state.dashboard_bootstrap.peek().expect("startup value");
    let out = before_epoch(&state, redeem(&value, Some(&live))).await;
    assert!(
        out.set_cookie().is_empty(),
        "no session issued and none cleared: {} {}",
        out.status,
        out.set_cookie()
    );
    assert_eq!(
        state.dashboard_bootstrap.peek().as_deref(),
        Some(value.as_str()),
        "the link is kept"
    );
    assert!(is_admin_view(&send(&state, get(STATUS, Some(&live))).await));
    let later = send(&state, redeem(&value, None)).await;
    assert!(
        !later.set_cookie().is_empty() && !later.clears_cookie(),
        "the same link redeems once the clock reads: {} {}",
        later.status,
        later.set_cookie()
    );
}
