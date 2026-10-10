// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8046: a check-site caller that joins another request's tool fill
//! classifies its own deadline by what that fill did. A fill that handed its
//! request to the transport is waiting on the backend, so the joiner's timeout
//! is the backend's, even while a login of its cohort is in flight; a fill
//! still waiting on that login leaves the joiner `AuthorizationPending`.

use super::login_window::{Upstream, approved_start, spawn_call, variant, within};
use super::token_lapse::{Pages, arrived, lapse};
use super::*;

/// The caller that owns the fill: discovery's `DrainBudget` path, which runs
/// under no deadline of its own.
fn spawn_discovery(backend: &Arc<Backend>) -> tokio::task::JoinHandle<Result<Arc<Vec<Tool>>>> {
    let backend = Arc::clone(backend);
    tokio::spawn(async move { backend.get_tools_for_binding(None, &[]).await })
}

/// The joiner: a check-site fill on the same slot, bounded by its own
/// call timeout (plus the wait grace).
fn spawn_check(
    backend: &Arc<Backend>,
) -> tokio::task::JoinHandle<Result<(Arc<Vec<Tool>>, super::super::fill_check::Completeness)>> {
    let backend = Arc::clone(backend);
    tokio::spawn(async move { backend.tools_for_check(None, &[], false).await })
}

/// `MIK-8046.PROV.2`: the owner's first page went to the transport (its
/// token was good) and its second never comes. A request-time login then
/// opens in the cohort the joiner captured. When the joiner's deadline passes,
/// the fill it joined was waiting on the backend, not on the login.
#[tokio::test]
async fn a_joiner_of_a_dispatched_fill_times_out_as_the_backend() {
    static PAGES: Pages = Pages::new();
    // Owner at t0: page 1 answers at 2 s, page 2 times out at its 10 s
    // transport bound (about 12 s). The joiner enters once the owner's first
    // page is in flight, so its 10 s + 1 s deadline passes while the owner
    // still waits.
    let (backend, browser, _dir) = approved_start(
        Upstream::ListStallsCounted(Duration::from_secs(2), &PAGES),
        Duration::from_secs(10),
    )
    .await;
    let owner = spawn_discovery(&backend);
    arrived(&PAGES.first, 1, "the owner's first page").await;
    let joiner = spawn_check(&backend);

    // The owner has sent its second page before the token lapses.
    arrived(&PAGES.second, 1, "the owner's second page").await;
    lapse(&backend).await;
    let call = spawn_call(&backend);
    browser
        .opened(2, "another caller's request-time login")
        .await;
    assert!(
        !joiner.is_finished(),
        "the login must open before the joiner's deadline, or the row tests nothing"
    );

    let error = within("the joiner's own deadline", joiner)
        .await
        .expect("joiner task")
        .expect_err("the upstream never answered the list in time");
    assert!(
        !owner.is_finished(),
        "the owner must still be waiting, or the joiner read the owner's error"
    );
    assert_eq!(
        PAGES.first.load(Ordering::SeqCst),
        1,
        "the joiner sent no first page of its own: it joined the owner's fill"
    );
    assert!(
        variant(&error).starts_with("BackendUnavailable"),
        "a joined fill that was handed to the transport timed out on the backend: {error:?}"
    );
    call.abort();
    owner.abort();
}

/// Control: the owner's token lapsed first, so the owner's own token step is
/// the request-time login, and the fill it runs has handed nothing to the
/// transport. The joiner's deadline passes while it waits on that login:
/// `AuthorizationPending` stays.
#[tokio::test]
async fn a_joiner_of_a_fill_waiting_on_the_login_times_out_as_authorization_pending() {
    let (backend, browser, _dir) = approved_start(Upstream::Plain, Duration::from_secs(1)).await;
    lapse(&backend).await;
    let owner = spawn_discovery(&backend);
    browser
        .opened(2, "the owner fill's request-time login")
        .await;
    let joiner = spawn_check(&backend);

    let error = within("the joiner's own deadline", joiner)
        .await
        .expect("joiner task")
        .expect_err("no tools while the owner's login is pending");
    assert!(
        !owner.is_finished(),
        "the owner must still be waiting on its login, or the row tests nothing"
    );
    assert!(
        variant(&error).starts_with("AuthorizationPending"),
        "a joined fill waiting on its login leaves the joiner AuthorizationPending: {error:?}"
    );
    owner.abort();
}
