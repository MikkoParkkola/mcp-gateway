// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8339: a request-time login belongs to a detached task, not to the
//! caller that began it. A caller bounded by a deadline (a fill, a warm-start
//! attempt, a task-recovery claim) drops only its own wait: the login stays
//! open, and the person who approves it after the deadline gets a token the
//! next request uses, with no second browser.

use super::login_window::{Upstream, approved_start, spawn_call, variant, within};
use super::*;

/// Play the person approving `url`, and report whether its callback was still
/// listening. Unlike `login_window::approve`, a closed listener is an answer
/// here, not a fixture failure: it is exactly how a login abandoned by its
/// caller's deadline shows itself.
async fn approve_if_listening(url: &str) -> bool {
    let parsed = url::Url::parse(url).unwrap();
    let query: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
    let callback = url::Url::parse_with_params(
        &query["redirect_uri"],
        &[
            ("code", "login-window-code"),
            ("state", query["state"].as_str()),
        ],
    )
    .unwrap();
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(callback)
        .send()
        .await
        .is_ok()
}

/// LOGINDL.2: a fill whose deadline fires during the request-time login it
/// began leaves that login open. Approving it afterwards stores the token,
/// and the next request uses it: the browser opened twice in all.
#[tokio::test]
async fn a_fill_deadline_leaves_its_request_time_login_open() {
    let (backend, browser, _dir) = approved_start(Upstream::Plain, Duration::from_secs(1)).await;
    super::token_lapse::lapse(&backend).await;
    // Premise: no login is in flight before the fill, so the one that opens
    // is the fill's own.
    assert_eq!(browser.opens(), 1, "premise: only the start's login");
    assert!(
        !backend.login_gate.in_flight(),
        "premise: no login in flight before the fill"
    );

    let error = within(
        "the fill's own deadline",
        Box::pin(backend.tools_for_check(None, &[], false)),
    )
    .await
    .expect_err("no tools while the request-time login is pending");
    assert!(
        variant(&error).starts_with("AuthorizationPending"),
        "premise: the fill's deadline fired during the login: {error:?}"
    );
    let url = browser.opened(2, "the fill's request-time login").await;

    assert!(
        approve_if_listening(&url).await,
        "the login the fill began was gone when the person approved it"
    );
    let call = within("the next request", spawn_call(&backend))
        .await
        .expect("call task");
    assert!(
        call.is_ok(),
        "the approved login's token serves the next request: {call:?}"
    );
    assert_eq!(
        browser.opens(),
        2,
        "the next request opened another login instead of using the approved one"
    );
}
