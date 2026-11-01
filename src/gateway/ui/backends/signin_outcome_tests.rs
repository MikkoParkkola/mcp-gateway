// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One outcome per sign-in attempt: the login gate ends with what the decision
//! really was, only after the decision has settled, and a backend restart ends
//! a held grant. Joiners are serving clients that wait on the shared login.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use tokio::task::JoinHandle;

use super::fixture::{Gw, Who};
use crate::Error;
use crate::backend::sign_in_flow::SignInWindows;
use crate::oauth::client::authorize_tests::client;
use crate::test_wait::HANG_BOUND;

/// A serving client waiting on the backend's shared login.
pub(super) fn joiner(gw: &Gw) -> JoinHandle<crate::Result<String>> {
    let waiting = client(gw.store.path(), Some(&gw.issuer))
        .with_login_gate(Arc::clone(&gw.backend.login_gate));
    tokio::spawn(async move { waiting.authorize_shared(true, None).await })
}

/// Let spawned tasks run until the joiner is parked on the login.
pub(super) async fn parked() {
    for _ in 0..500 {
        tokio::task::yield_now().await;
    }
}

/// A started, approved sign-in whose grant is held.
pub(super) async fn held(gw: &Gw) -> (Who, String) {
    let owner = gw.session();
    let (url, attempt) = Gw::link(&gw.start(&owner).await);
    let _ = gw.approve(&url).await;
    gw.wait_until_held().await;
    (owner, attempt)
}

pub(super) fn windows(start: u64, confirm: u64) -> SignInWindows {
    SignInWindows {
        start: Duration::from_secs(start),
        confirm: Duration::from_secs(confirm),
    }
}

/// What a joiner is told, bounded.
pub(super) async fn told(joined: JoinHandle<crate::Result<String>>) -> Error {
    tokio::time::timeout(HANG_BOUND, joined)
        .await
        .expect("the joiner is told within the bound")
        .expect("the joiner ran")
        .expect_err("a sign-in that did not commit is not a success")
}

fn is_cancelled(error: &Error) -> bool {
    matches!(error, Error::AuthorizationCancelled { .. })
}

#[cfg(unix)]
fn is_no_token(error: &Error) -> bool {
    error.to_string().contains("stored no token")
}

/// Read-only store: the confirm's write fails.
#[cfg(unix)]
fn deny_writes(gw: &Gw) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(gw.store.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
}

#[cfg(unix)]
fn allow_writes(gw: &Gw) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(gw.store.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
}

// A cancel ends the shared login as cancelled, not as a success that stored
// nothing. Red today: the owner's cancel ends the lead with success.
#[tokio::test]
async fn a_joiner_of_a_cancelled_ui_login_gets_cancelled() {
    let gw = Gw::new().await;
    let (owner, attempt) = held(&gw).await;
    let waiting = joiner(&gw);
    parked().await;

    let cancel = gw.confirm(&owner, &attempt, "cancel").await;

    assert_eq!(cancel.status, StatusCode::OK, "{}", cancel.body);
    let error = told(waiting).await;
    assert!(is_cancelled(&error), "{error}");
}

// A failed save ends the shared login with the save's error. Red today: it
// ends with success, so the joiner reads "stored no token".
#[cfg(unix)]
#[tokio::test]
async fn a_joiner_of_a_failed_save_gets_the_save_error() {
    let gw = Gw::new().await;
    let (owner, attempt) = held(&gw).await;
    let waiting = joiner(&gw);
    parked().await;
    deny_writes(&gw);

    let confirm = gw.confirm(&owner, &attempt, "confirm").await;
    allow_writes(&gw);

    assert!(confirm.status.is_server_error(), "{}", confirm.body);
    let error = told(waiting).await;
    assert!(!is_cancelled(&error) && !is_no_token(&error), "{error}");
}

// `hold`'s empty-slot return: the flow was taken between the exchange and the
// store (parked at the hold pause), so the attempt ends cancelled. Red today:
// it ends with success.
#[tokio::test]
async fn a_hold_that_finds_its_flow_gone_ends_the_login_cancelled() {
    let gw = Arc::new(Gw::new().await);
    let (reached, release) = gw.backend.sign_in.hold_pause.arm();
    let owner = gw.session();
    let (url, attempt) = Gw::link(&gw.start(&owner).await);
    let _ = gw.approve(&url).await;
    crate::test_pause::within("the task reaches its hold", reached.notified()).await;
    let waiting = joiner(&gw);
    parked().await;
    // The cancel answers once the gate reflects it, after the parked task.
    let cancel = tokio::spawn({
        let gw = Arc::clone(&gw);
        async move { gw.confirm(&owner, &attempt, "cancel").await }
    });
    parked().await;

    release.notify_one();

    let cancel = cancel.await.expect("the request ran");
    assert_eq!(cancel.status, StatusCode::OK, "{}", cancel.body);
    let error = told(waiting).await;
    assert!(is_cancelled(&error), "{error}");
}

// A restart (the gate's cancel) ends a held grant at once, and the grant can
// no longer be confirmed. Red today: `hold` ignores the cancel, so the restart
// waits for the confirm window.
#[tokio::test]
async fn a_backend_restart_ends_a_held_grant_and_it_cannot_be_confirmed() {
    let gw = Gw::new().await;
    let (owner, attempt) = held(&gw).await;

    let ended = tokio::time::timeout(HANG_BOUND, gw.backend.login_gate.cancel_and_join()).await;

    assert!(ended.is_ok(), "the restart waited out the confirm window");
    let confirm = gw.confirm(&owner, &attempt, "confirm").await;
    assert_eq!(confirm.status, StatusCode::NOT_FOUND, "{}", confirm.body);
    assert!(gw.saved().is_none());
}

// A confirm dropped after it took the grant is read as a cancel. Red today:
// nothing tells the flow task, which waits out the window.
#[tokio::test]
async fn a_dropped_confirm_reads_as_cancelled() {
    let gw = Arc::new(Gw::new().await);
    let (owner, attempt) = held(&gw).await;
    let waiting = joiner(&gw);
    parked().await;
    let (reached, release) = gw.backend.sign_in.commit_pause.arm();
    // The decision itself, not a request: the audit layer runs a handler on a
    // task of its own so a write still commits after its client left, which
    // would keep this future alive. Dropping `decide` is the claim.
    let Who::Dashboard(handle) = owner else {
        panic!("a session owner");
    };
    let tag = crate::gateway::record_principal::sign_in_owner(&gw.state.record_key(), &handle);
    let request = tokio::spawn({
        let gw = Arc::clone(&gw);
        async move {
            super::super::signin_flow::decide(
                &gw.state,
                &gw.backend,
                &tag,
                &attempt,
                super::super::signin_flow::Decision::Confirm,
            )
            .await
        }
    });
    crate::test_pause::within("the confirm reaches its commit", reached.notified()).await;

    request.abort();
    let _ = request.await;
    release.notify_one();

    let error = told(waiting).await;
    assert!(is_cancelled(&error), "{error}");
    assert!(gw.saved().is_none());
}

// The backend's cancel has been signalled but the flow task has not yet taken
// the flow: a confirm in that window must be refused, not commit a login the
// backend already cancelled. The decision is called directly so nothing yields
// between the signal and the confirm. Red today: `take_for` never looks at
// the cancel.
#[tokio::test]
async fn a_confirm_after_the_backend_cancel_signal_is_refused() {
    let gw = Arc::new(Gw::new().await);
    let (owner, attempt) = held(&gw).await;
    let Who::Dashboard(handle) = owner else {
        panic!("a session owner");
    };
    let tag = crate::gateway::record_principal::sign_in_owner(&gw.state.record_key(), &handle);
    gw.backend
        .with_flow(|slot| slot.as_ref().map(|flow| flow.cancel.cancel()))
        .expect("the flow is pending");

    let decided = super::super::signin_flow::decide(
        &gw.state,
        &gw.backend,
        &tag,
        &attempt,
        super::super::signin_flow::Decision::Confirm,
    )
    .await;

    assert!(
        matches!(decided, super::super::signin_flow::Decided::NoSignIn),
        "a cancelled login is not confirmed"
    );
    assert!(gw.saved().is_none(), "nothing was saved");
}
