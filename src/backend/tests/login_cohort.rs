// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8339 start-path rows. LOGINDL.8: a start queued behind a login that
//! then fails shares that failure, recorded on the cohort it captured before
//! it queued, rather than discovering again and opening a login of its own.
//! LOGINDL.24: a reconnect waiting for its OAuth client ends at its bound.

use super::login_window::{
    Browser, approve, counted_authorization_server, login_backend, spawn_start, variant, within,
};
use super::*;

#[tokio::test]
async fn a_start_queued_behind_a_failed_login_shares_its_outcome() {
    let (origin, discovered) = counted_authorization_server().await;
    let dir = tempfile::tempdir().unwrap();
    let browser = Browser::new();
    let backend = login_backend(&origin, dir.path(), &browser, Duration::from_secs(30), None);

    let first = spawn_start(&backend);
    let url = browser
        .opened(1, "the first start opening the browser")
        .await;
    // Queued on the start lock the first start holds through its login, with
    // the login's cohort captured before it queued.
    let queued = spawn_start(&backend);
    tokio::task::yield_now().await;
    assert_eq!(
        discovered.load(Ordering::SeqCst),
        1,
        "premise: one discovery so far"
    );

    // The token endpoint refuses the code: the login fails.
    approve(&url).await;
    let first_error = within("the first start", first)
        .await
        .expect("start task")
        .expect_err("the token endpoint refused the code");
    let shared = within("the queued start", queued)
        .await
        .expect("start task")
        .expect_err("the queued start shares the failed login's end");

    assert!(
        variant(&first_error).starts_with("OAuth") && variant(&shared) == variant(&first_error),
        "the queued start returns the failed login's typed error: {first_error:?} / {shared:?}"
    );
    assert_eq!(
        browser.opens(),
        1,
        "the queued start opened no login of its own"
    );
    assert_eq!(
        discovered.load(Ordering::SeqCst),
        1,
        "the queued start shared the outcome without discovering again"
    );
}

/// LOGINDL.24: a transport re-connecting after its session expired, whose
/// connect waits for the OAuth client another task holds (a login or a
/// refresh), gives up at its own bound (`startup.rs`, the connect client-wait
/// arm), so the caller gets its answer instead of waiting on the client
/// however long it is held. A failed re-handshake returns the caller's own
/// session-expired answer (`transport_impl.rs`), which is what the row reads.
#[tokio::test]
async fn a_reconnect_waiting_for_its_oauth_client_ends_at_its_bound() {
    use super::login_detach::{advance_paused, oauth_client_of};
    use super::login_window::{Upstream, approved_start, spawn_call};
    static SEEN: AtomicUsize = AtomicUsize::new(0);
    let (backend, _browser, _dir) = approved_start(
        Upstream::SessionExpires(Duration::from_secs(2), &SEEN),
        Duration::from_secs(3600),
    )
    .await;
    let before = SEEN.load(Ordering::SeqCst);
    let call = spawn_call(&backend);
    // The call's request reached the server on a live token; its
    // session-expired answer comes 2 s later. Meanwhile another task takes
    // the client.
    super::token_lapse::arrived(&SEEN, before + 1, "the call's request").await;
    let client = oauth_client_of(&backend);
    let held = client.lock().await;
    // The test holds the client, so nothing left can race paused time. The
    // first jump also completes the server's 2 s delay, which starts the
    // reconnect; the next passes the reconnect's own bound. Three jumps at
    // most, so the call's own 3600 s timeout is never reached.
    // Between jumps, poll: the server's answer still crosses a real socket.
    'jumps: for _ in 0..3 {
        advance_paused(crate::oauth::OAUTH_AUTHORIZATION_WINDOW + Duration::from_secs(1)).await;
        for _ in 0..50 {
            if call.is_finished() {
                break 'jumps;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    let answered = within("the call's answer", call).await.expect("call task");
    drop(held);
    assert!(
        format!("{answered:?}").contains("session not found"),
        "the caller got its own session-expired answer: {answered:?}"
    );
}
