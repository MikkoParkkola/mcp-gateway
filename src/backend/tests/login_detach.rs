// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8339: a request-time login belongs to a detached task, not to the
//! caller that began it. A caller bounded by a deadline (a fill, a warm-start
//! attempt, a task-recovery claim) drops only its own wait: the login stays
//! open, and the person who approves it after the deadline gets a token the
//! next request uses, with no second browser.

use super::login_window::{
    Upstream, approve_if_listening, approved_start, spawn_call, variant, within,
};
use super::*;

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

/// LOGINDL.6: single-flight. Five callers whose deadlines all fire during one
/// request-time login, then retry after the person approves it: one login in
/// all, and every retry is served by its token.
#[tokio::test]
async fn callers_retrying_after_their_deadlines_share_one_login() {
    let (backend, browser, _dir) = approved_start(Upstream::Plain, Duration::from_secs(1)).await;
    super::token_lapse::lapse(&backend).await;
    assert_eq!(browser.opens(), 1, "premise: only the start's login");

    let fills: Vec<_> = (0..5)
        .map(|_| {
            let backend = Arc::clone(&backend);
            tokio::spawn(async move { backend.tools_for_check(None, &[], false).await })
        })
        .collect();
    for fill in fills {
        let outcome = within("a fill's own deadline", fill)
            .await
            .expect("fill task");
        assert!(
            outcome.is_err(),
            "premise: no tools while the login is pending"
        );
    }
    let url = browser.opened(2, "the one request-time login").await;
    let listening = approve_if_listening(&url).await;

    let retries: Vec<_> = (0..5).map(|_| spawn_call(&backend)).collect();
    let mut served = 0;
    for retry in retries {
        if let Ok(Ok(Ok(_))) = tokio::time::timeout(Duration::from_secs(10), retry).await {
            served += 1;
        }
    }
    assert_eq!(
        browser.opens(),
        2,
        "the retries opened another login (approval reached a listener: {listening})"
    );
    assert_eq!(served, 5, "every retry is served by the one approved login");
}

/// LOGINDL.7: a detached login nobody approves ends at its own authorization
/// window, and records that on its cohort: `AuthorizationIncomplete`, not the
/// `Cancelled` of a login dropped with its caller.
#[tokio::test]
async fn an_unapproved_detached_login_ends_at_its_own_window() {
    let (backend, browser, _dir) = approved_start(Upstream::Plain, Duration::from_secs(1)).await;
    super::token_lapse::lapse(&backend).await;
    let cohort = backend.login_gate.cohort();

    let fill = within(
        "the fill's own deadline",
        Box::pin(backend.tools_for_check(None, &[], false)),
    )
    .await;
    assert!(fill.is_err(), "premise: the fill's deadline fired");
    browser.opened(2, "the fill's request-time login").await;

    // Only the callback wait and its timers remain: the window can pass on
    // paused time.
    tokio::time::pause();
    let ended = tokio::time::timeout(Duration::from_secs(301), async {
        while backend.login_gate.in_flight() {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await;
    tokio::time::resume();
    assert!(
        ended.is_ok(),
        "the detached login outlived its 300 s window"
    );

    assert!(
        matches!(
            cohort.outcome(),
            Some(crate::oauth::login_gate::LoginOutcome::Incomplete { .. })
        ),
        "the window's end is recorded on the cohort as Incomplete: {:?}",
        cohort.outcome()
    );
}

/// LOGINDL.12: closing a backend never logs in. Stopping a backend whose
/// token has lapsed still sends its session `DELETE`, and its header build
/// opens no browser: a close uses or refreshes a credential, never a login.
#[tokio::test]
async fn a_stop_sends_its_session_delete_without_a_login() {
    static DELETES: AtomicUsize = AtomicUsize::new(0);
    let (backend, browser, _dir) =
        approved_start(Upstream::SessionHeld(&DELETES), Duration::from_secs(1)).await;
    super::token_lapse::lapse(&backend).await;
    assert_eq!(browser.opens(), 1, "premise: only the start's login");
    assert_eq!(DELETES.load(Ordering::SeqCst), 0, "premise: no close yet");

    let stopped = tokio::time::timeout(Duration::from_secs(20), backend.stop()).await;

    assert_eq!(browser.opens(), 1, "the stop's header build opened a login");
    assert!(stopped.is_ok(), "the stop did not return");
    assert_eq!(
        DELETES.load(Ordering::SeqCst),
        1,
        "premise: the stop reached its session DELETE (its header build ran)"
    );
}
