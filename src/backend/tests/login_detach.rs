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

/// LOGINDL.13: the waited mark lands on the caller's own Provenance even
/// though the detached task, not the caller, runs the login. Read after that
/// login has ended (no attempt in flight, no outcome on the cohort, nothing
/// dispatched), so only the waited bit can make the deadline
/// `AuthorizationPending`. Green at base (the login runs in the caller's
/// scope); after the change it fails if the task does not carry the scopes.
#[tokio::test]
async fn a_detached_login_marks_its_callers_own_provenance_waited() {
    use crate::oauth::login_gate::Provenance;
    let (backend, browser, _dir) = approved_start(Upstream::Plain, Duration::from_secs(5)).await;
    super::token_lapse::lapse(&backend).await;
    assert!(
        !backend.login_gate.in_flight(),
        "premise: no login in flight, so the caller marks nothing before its token step"
    );

    let cohort = backend.login_gate.cohort();
    let classified = Provenance::scope(&backend.login_gate, async {
        // The caller's deadline, as an event: its request is dropped the
        // moment the login it began opens the browser.
        let mut request = Box::pin(backend.request("tools/list", None));
        let url = tokio::select! {
            done = &mut request => panic!("premise: the request ended without a login: {done:?}"),
            url = browser.opened(2, "the caller's request-time login") => url,
        };
        drop(request);
        approve_if_listening(&url).await;
        within("the login to end", async {
            while backend.login_gate.in_flight() {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        // Premise: no recorded end, so only the waited bit can classify.
        assert!(
            cohort.outcome().is_none(),
            "premise: the cohort recorded an end: {:?}",
            cohort.outcome()
        );
        Provenance::expired(
            "login-window",
            Error::BackendTimeout("login-window".to_string()),
        )
    })
    .await;

    assert!(
        variant(&classified).starts_with("AuthorizationPending"),
        "the login the caller waited on did not mark the caller's own Provenance: {classified:?}"
    );
}

/// LOGINDL.16: a caller whose token arrives from the detached login it waited
/// on, and whose own request then stalls, timed out on the backend, not on
/// the login: `mark_dispatched` runs on the joined success too. Green at base
/// (the inline token step marks it); after the change it fails if the joined
/// path skips the mark.
#[tokio::test]
async fn a_fill_served_by_its_approved_login_then_stalled_is_a_backend_timeout() {
    static PAGES: super::token_lapse::Pages = super::token_lapse::Pages::new();
    let (backend, browser, _dir) = approved_start(
        Upstream::ListStallsCounted(Duration::ZERO, &PAGES),
        Duration::from_secs(10),
    )
    .await;
    super::token_lapse::lapse(&backend).await;
    let first_pages = PAGES.first.load(Ordering::SeqCst);

    let fill = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.tools_for_check(None, &[], false).await })
    };
    let url = browser.opened(2, "the fill's request-time login").await;
    assert!(
        approve_if_listening(&url).await,
        "premise: the fill was still waiting when the person approved"
    );
    super::token_lapse::arrived(&PAGES.first, first_pages + 1, "the fill's first page").await;

    let error = within("the fill's own deadline", fill)
        .await
        .expect("fill task")
        .expect_err("the second page never comes");
    assert!(
        !variant(&error).starts_with("AuthorizationPending"),
        "a fill that sent its pages timed out on the backend, not the login: {error:?}"
    );
}

/// A fill on `backend` whose deadline fires during the request-time login it
/// began: returns that login's authorization URL.
async fn fill_abandons_a_login(
    backend: &Arc<Backend>,
    browser: &super::login_window::Browser,
) -> String {
    let fill = within(
        "the fill's own deadline",
        Box::pin(backend.tools_for_check(None, &[], false)),
    )
    .await;
    assert!(fill.is_err(), "premise: the fill's deadline fired");
    browser.opened(2, "the fill's request-time login").await
}

/// LOGINDL.4 (restart): a restart ends the request-time login a fill left
/// open, so approving it afterwards reaches no listener. Green at base, where
/// the deadline already ended it; after the change it fails if the detached
/// task ignores the Lead's cancel.
#[tokio::test]
async fn a_restart_ends_a_detached_request_time_login() {
    let (backend, browser, _dir) = approved_start(Upstream::Plain, Duration::from_secs(1)).await;
    super::token_lapse::lapse(&backend).await;
    let url = fill_abandons_a_login(&backend, &browser).await;

    let restart = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.force_restart().await })
    };
    browser.opened(3, "the restart's own login").await;
    assert!(
        !approve_if_listening(&url).await,
        "the restart left the fill's request-time login open"
    );
    restart.abort();
}

/// LOGINDL.4 (stop): a stop ends the request-time login a fill left open.
#[tokio::test]
async fn a_stop_ends_a_detached_request_time_login() {
    let (backend, browser, _dir) = approved_start(Upstream::Plain, Duration::from_secs(1)).await;
    super::token_lapse::lapse(&backend).await;
    let url = fill_abandons_a_login(&backend, &browser).await;

    within("the stop", backend.stop())
        .await
        .expect("the stop succeeds");
    assert!(
        !approve_if_listening(&url).await,
        "the stop left the fill's request-time login open"
    );
    assert!(
        !backend.login_gate.in_flight(),
        "a login is still in flight after the stop"
    );
}

/// LOGINDL.11: a forced restart's own start leads a fresh login: it captures
/// its cancel epoch and cohort after its own cancel, so it never shares the
/// `Cancelled` it caused.
#[tokio::test]
async fn a_forced_restart_leads_a_fresh_login_after_its_own_cancel() {
    let (backend, browser, _dir) = approved_start(Upstream::Plain, Duration::from_secs(1)).await;
    super::token_lapse::lapse(&backend).await;
    fill_abandons_a_login(&backend, &browser).await;

    let restart = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.force_restart().await })
    };
    let url = browser.opened(3, "the restart's own fresh login").await;
    super::login_window::approve(&url).await;
    let restarted = within("the restart", restart).await.expect("restart task");
    assert!(
        restarted.is_ok(),
        "the restart shared a cancelled login instead of leading its own: {restarted:?}"
    );
}

/// LOGINDL.9: a deadline that fires during a stalled REFRESH, with no login
/// open, is the backend's timeout, not `AuthorizationPending`: the caller
/// marks itself waited only when a login is actually in flight. Green at base
/// (the refresh runs inline and marks nothing); after the change it fails if
/// the caller marks waited unconditionally before detaching.
#[tokio::test]
async fn a_deadline_during_a_stalled_refresh_is_not_a_pending_login() {
    let (backend, browser, _dir) = super::login_window::approved_start_full(
        Upstream::Plain,
        Duration::from_secs(1),
        super::login_window::Account::PerUser,
        super::login_window::TokenEndpoint::RefreshStalls,
    )
    .await;
    super::token_lapse::lapse(&backend).await;
    assert!(
        !backend.login_gate.in_flight(),
        "premise: no login in flight"
    );

    let error = within(
        "the fill's own deadline",
        Box::pin(backend.tools_for_check(None, &[], false)),
    )
    .await
    .expect_err("the refresh never answers");

    assert_eq!(browser.opens(), 1, "premise: a refresh, not a login");
    assert!(
        !variant(&error).starts_with("AuthorizationPending"),
        "a deadline spent on a refresh is not a pending login: {error:?}"
    );
}

/// LOGINDL.18a: a stop ends a login whose code exchange stalled after the
/// person approved: the exchange waits under the Lead's cancel, so the stop
/// returns, and the caller ends `AuthorizationCancelled`. Red at base: the
/// exchange is not cancellable, and the stop waits on it.
#[tokio::test]
async fn a_stop_ends_a_login_stalled_in_its_code_exchange() {
    static EXCHANGES: AtomicUsize = AtomicUsize::new(0);
    let (backend, browser, _dir) = super::login_window::approved_start_full(
        Upstream::Plain,
        Duration::from_secs(30),
        super::login_window::Account::PerUser,
        super::login_window::TokenEndpoint::ExchangeStallsAfter(1, &EXCHANGES),
    )
    .await;
    super::token_lapse::lapse(&backend).await;

    let call = spawn_call(&backend);
    let url = browser.opened(2, "the call's request-time login").await;
    assert!(
        approve_if_listening(&url).await,
        "premise: the login was listening"
    );
    super::token_lapse::arrived(&EXCHANGES, 2, "the stalled code exchange").await;

    let stopped = tokio::time::timeout(Duration::from_secs(20), backend.stop()).await;
    assert!(
        stopped.is_ok(),
        "the stop waited on a stalled code exchange"
    );
    let called = within("the call", call).await.expect("call task");
    let error = called.expect_err("a stopped backend's login stores no token");
    assert!(
        variant(&error).starts_with("AuthorizationCancelled"),
        "the stalled login ends Cancelled: {error:?}"
    );
}

/// LOGINDL.18b: a login whose token save waits on the credential's
/// cross-process lock (another gateway process holds it) ends at its own
/// bound, recorded on the cohort as `AuthorizationIncomplete`. The code
/// exchange before it is bounded by the OAuth client's own 30 s timeout
/// (oauth/client/destination.rs:86), so the save-lock wait is the one place
/// the Lead stage's bound acts. Red at base: that wait is unbounded.
#[tokio::test]
async fn a_login_waiting_on_a_held_credential_lock_ends_at_its_bound() {
    let (backend, browser, _dir) = approved_start(Upstream::Plain, Duration::from_secs(30)).await;
    super::token_lapse::lapse(&backend).await;
    let client = backend
        .last_oauth_client
        .lock()
        .clone()
        .expect("premise: a start built an OAuth client");
    let lock_path = client.lock().await.credential_lock_path_for_test();
    let held = crate::fs_lock::ExclusiveFileLock::acquire(&lock_path)
        .expect("another process holds the credential lock");
    // Counted after the test's own hold: only the login's attempts move it.
    let held_attempts = crate::fs_lock::lock_attempts(&lock_path);
    let cohort = backend.login_gate.cohort();

    let _call = spawn_call(&backend);
    let url = browser.opened(2, "the call's request-time login").await;
    assert!(
        approve_if_listening(&url).await,
        "premise: the login was listening"
    );
    within("the save to wait on the held lock", async {
        while crate::fs_lock::lock_attempts(&lock_path) == held_attempts {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;

    // The exchange is done and the save polls a file lock: no I/O is left
    // to race, so the bound can pass on paused time.
    tokio::time::pause();
    let ended = tokio::time::timeout(Duration::from_secs(301), async {
        while backend.login_gate.in_flight() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await;
    tokio::time::resume();
    drop(held);

    assert!(
        ended.is_ok(),
        "the save-lock wait outlived the login's bound"
    );
    assert!(
        matches!(
            cohort.outcome(),
            Some(crate::oauth::login_gate::LoginOutcome::Incomplete { .. })
        ),
        "the bound's end is recorded on the cohort as Incomplete: {:?}",
        cohort.outcome()
    );
}

/// The started backend's OAuth client, as a login holding it would be.
fn oauth_client_of(backend: &Backend) -> Arc<tokio::sync::Mutex<crate::oauth::OAuthClient>> {
    backend
        .last_oauth_client
        .lock()
        .clone()
        .expect("premise: a start built an OAuth client")
}

/// LOGINDL.10: a non-interactive caller (the health probe's kind) whose
/// client mutex a login holds gets `AuthorizationRequired` at once, and never
/// detaches a token step (MIK-7982 C2 kept).
#[tokio::test]
async fn a_non_interactive_caller_never_detaches_onto_a_held_client() {
    let (backend, _browser, _dir) = approved_start(Upstream::Plain, Duration::from_secs(5)).await;
    super::token_lapse::lapse(&backend).await;
    let client = oauth_client_of(&backend);
    let held = client.lock().await;
    // Counted after setup: only this caller could move it.
    let before = backend.login_gate.detached_for_test();

    let outcome = within(
        "the non-interactive request",
        crate::oauth::login_gate::non_interactive(backend.request("tools/list", None)),
    )
    .await;
    drop(held);

    let error = outcome.expect_err("the client is held");
    assert!(
        variant(&error).starts_with("AuthorizationRequired"),
        "a non-interactive caller answers at once: {error:?}"
    );
    assert_eq!(
        backend.login_gate.detached_for_test(),
        before,
        "a non-interactive caller detached a token step"
    );
}

/// LOGINDL.15: a detached token step still waiting for the client (before it
/// leads or joins any login) observes a restart: its caller ends
/// `AuthorizationCancelled` instead of waiting out its own bound.
#[tokio::test]
async fn a_restart_ends_a_detached_step_waiting_for_its_client() {
    let (backend, _browser, _dir) = approved_start(Upstream::Plain, Duration::from_secs(30)).await;
    super::token_lapse::lapse(&backend).await;
    let client = oauth_client_of(&backend);
    let held = client.lock().await;
    let before = backend.login_gate.detached_for_test();

    let call = spawn_call(&backend);
    within("the call's token step to detach", async {
        while backend.login_gate.detached_for_test() == before {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let restart = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.force_restart().await })
    };
    let called = within("the call", call).await.expect("call task");
    restart.abort();
    drop(held);

    let error = called.expect_err("the restart revoked the waiting step");
    assert!(
        variant(&error).starts_with("AuthorizationCancelled"),
        "a revoked step waiting for its client ends Cancelled: {error:?}"
    );
}

/// LOGINDL.17: a detached step whose own bound passes before it leads or
/// joins a login, with no login of its cohort in flight and none recorded,
/// is the backend's timeout, not `AuthorizationIncomplete` (reserved for a
/// login that actually ran).
#[tokio::test]
async fn a_detached_steps_bound_with_no_login_is_a_backend_timeout() {
    let (backend, _browser, _dir) =
        approved_start(Upstream::Plain, Duration::from_secs(3600)).await;
    super::token_lapse::lapse(&backend).await;
    let client = oauth_client_of(&backend);
    let held = client.lock().await;
    let before = backend.login_gate.detached_for_test();

    let call = spawn_call(&backend);
    within("the call's token step to detach", async {
        while backend.login_gate.detached_for_test() == before {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    // The step waits on a mutex this test holds: no I/O is left to race.
    tokio::time::pause();
    let called = tokio::time::timeout(Duration::from_secs(301), call).await;
    tokio::time::resume();
    drop(held);

    let error = called
        .expect("the step's own bound ends it")
        .expect("call task")
        .expect_err("no token while the client is held");
    assert!(
        matches!(error, Error::BackendTimeout(_)),
        "a bound with no login in flight is the backend's timeout: {error:?}"
    );
}
