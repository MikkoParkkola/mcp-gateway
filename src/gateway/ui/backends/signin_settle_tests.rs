// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A confirm's save and the gate: the gate stays held until the decision has
//! settled, a save that cannot finish by the flow's own end writes nothing,
//! and a backend cancel during a commit waits for that commit's outcome.

use std::sync::Arc;

use axum::http::StatusCode;

use super::fixture::Gw;
use super::outcome_tests::{held, joiner, parked, told, windows};
use crate::Error;
use crate::test_wait::HANG_BOUND;

// The outcome is paused on its way to the flow task. While it is paused the
// confirm call stays pending, the gate is in flight and a start is refused;
// only after the lead has published its outcome does the confirm answer. Red
// today: the confirm answers after a fixed number of yields whatever the lead
// has done, and the pause is never reached.
#[tokio::test]
async fn the_gate_stays_held_until_the_decision_settles() {
    let gw = Arc::new(Gw::new().await);
    let (owner, attempt) = held(&gw).await;
    let (reached, release) = gw.backend.sign_in.outcome_pause.arm();
    let confirm = tokio::spawn({
        let (gw, owner) = (Arc::clone(&gw), owner.clone());
        async move { gw.confirm(&owner, &attempt, "confirm").await }
    });
    tokio::time::timeout(HANG_BOUND, reached.notified())
        .await
        .expect("the outcome reaches its pause");

    for _ in 0..500 {
        tokio::task::yield_now().await;
    }
    assert!(
        !confirm.is_finished(),
        "the confirm answered before it settled"
    );
    assert!(
        gw.backend.login_gate.in_flight(),
        "the gate was released early"
    );
    assert_eq!(gw.start(&owner).await.status, StatusCode::CONFLICT);

    release.notify_one();
    let reply = tokio::time::timeout(HANG_BOUND, confirm)
        .await
        .expect("the confirm answers")
        .expect("the request ran");
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(
        !gw.backend.login_gate.in_flight(),
        "the gate is free once it answers"
    );
}

// A save that cannot get the credential lock by the flow's own end writes
// nothing: it expires at `until`, the confirm answers with the save's error,
// and the joiner is told the same. Red today: the save has a fresh window of
// its own, and the expiry arm releases the gate as a success mid-save.
#[tokio::test]
async fn a_confirm_save_blocked_past_the_window_ends_without_a_write() {
    let gw = Arc::new(Gw::new().await);
    gw.backend.set_sign_in_windows_for_test(windows(60, 2));
    let (owner, attempt) = held(&gw).await;
    let serving = gw
        .backend
        .sign_in
        .installed_client
        .lock()
        .clone()
        .expect("the fixture installs a client");
    let lock = serving.credential_lock_path_for_test();
    let _held = crate::fs_lock::ExclusiveFileLock::acquire(&lock).expect("the lock is free");
    let waiting = joiner(&gw);
    parked().await;
    let confirm = tokio::spawn({
        let gw = Arc::clone(&gw);
        async move { gw.confirm(&owner, &attempt, "confirm").await }
    });

    let reply = tokio::time::timeout(HANG_BOUND, confirm)
        .await
        .expect("the save ends at the flow's own end")
        .expect("the request ran");

    assert!(
        reply.status.is_server_error(),
        "{} {}",
        reply.status,
        reply.body
    );
    assert!(gw.saved().is_none(), "nothing was written");
    let error = told(waiting).await;
    assert!(
        !matches!(error, Error::AuthorizationCancelled { .. })
            && !error.to_string().contains("stored no token"),
        "{error}"
    );
}

// A backend cancel that lands while a confirm is committing waits for that
// commit's outcome. The commit is made to fail, so the lead must end with the
// commit's error: never Cancelled, and never success (a success would also
// come from a `hold` that ignores the cancel). Red today: the lead ends with
// success, so the joiner reads "stored no token".
#[cfg(unix)]
#[tokio::test]
async fn a_backend_cancel_during_a_confirm_commit_waits_for_its_outcome() {
    use std::os::unix::fs::PermissionsExt;
    let gw = Arc::new(Gw::new().await);
    let (owner, attempt) = held(&gw).await;
    let waiting = joiner(&gw);
    parked().await;
    let (reached, release) = gw.backend.sign_in.commit_pause.arm();
    let confirm = tokio::spawn({
        let gw = Arc::clone(&gw);
        async move { gw.confirm(&owner, &attempt, "confirm").await }
    });
    crate::test_pause::within("the confirm reaches its commit", reached.notified()).await;
    std::fs::set_permissions(gw.store.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let restart = tokio::spawn({
        let gw = Arc::clone(&gw);
        async move { gw.backend.login_gate.cancel_and_join().await }
    });
    for _ in 0..500 {
        tokio::task::yield_now().await;
    }

    release.notify_one();
    let reply = tokio::time::timeout(HANG_BOUND, confirm)
        .await
        .expect("the confirm answers")
        .expect("the request ran");
    std::fs::set_permissions(gw.store.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    assert!(reply.status.is_server_error(), "{}", reply.body);
    tokio::time::timeout(HANG_BOUND, restart)
        .await
        .expect("the restart finishes once the commit has")
        .expect("the restart ran");
    let error = told(waiting).await;
    assert!(
        !matches!(error, Error::AuthorizationCancelled { .. })
            && !error.to_string().contains("stored no token"),
        "{error}"
    );
}
