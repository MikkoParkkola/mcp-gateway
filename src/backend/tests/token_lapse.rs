// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8269: a token lapses when a row says so, not when a wall clock runs
//! out; and the start path's era probe, an optimisation, never opens a login.

use super::login_window::{Upstream, approve, approved_start, within};
use super::*;

/// `tools/list` pages an [`Upstream::ListStallsCounted`] server received:
/// first pages, and second pages (the ones that never answer).
#[derive(Default)]
pub(crate) struct Pages {
    pub first: AtomicUsize,
    pub second: AtomicUsize,
}

impl Pages {
    pub(super) const fn new() -> Self {
        Self {
            first: AtomicUsize::new(0),
            second: AtomicUsize::new(0),
        }
    }
}

/// Wait until `counter` reaches `n`: the server has received the request a
/// row must have sent before its token lapses.
pub(super) async fn arrived(counter: &AtomicUsize, n: usize, what: &str) {
    within(what, async {
        while counter.load(Ordering::SeqCst) < n {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
}

/// Lapse the started backend's OAuth token now, in memory and in storage, so
/// its next request's token step needs a login (MIK-8269). Replaces sleeping
/// out a token issued with a few seconds of use, which a slow runner can lose
/// mid-start.
pub(crate) async fn lapse(backend: &Backend) {
    let client = backend
        .last_oauth_client
        .lock()
        .clone()
        .expect("premise: a start built an OAuth client");
    client.lock().await.age_token_for_test().await;
}

/// The era probe (`era.rs`) is bounded at two seconds and documented never to
/// fail a start. Meeting a lapsed token, it must not lead a login: one it led
/// would open the browser, then be dropped with the probe and end `Cancelled`
/// for the start behind it. The start's own login still authorizes it.
#[tokio::test]
async fn an_era_probe_meeting_a_lapsed_token_opens_no_login() {
    let (backend, browser, _dir) = approved_start(Upstream::Plain, Duration::from_secs(5)).await;
    let transport = backend
        .shared_entry()
        .transport
        .read()
        .clone()
        .expect("premise: the backend started");
    lapse(&backend).await;

    let entry = backend.shared_entry();
    within(
        "the era probe",
        backend.resolve_era_for_entry_test(&transport, &entry),
    )
    .await;
    assert_eq!(browser.opens(), 1, "the era probe opened a login");

    // Control: the start's own login still authorizes a restart.
    let restart = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.force_restart().await })
    };
    let url = browser.opened(2, "the restart's own login").await;
    approve(&url).await;
    within("the restart completing with a token", restart)
        .await
        .expect("restart task")
        .expect("the restart's own login starts the backend");
}
