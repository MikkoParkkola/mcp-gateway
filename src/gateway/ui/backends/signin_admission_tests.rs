// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Admission before discovery, and a start request that goes away: a restart
//! during discovery refuses the start, discovery is bounded by the start
//! window, and a start dropped before its link releases the login.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;

use super::fixture::Gw;
use super::outcome_tests::windows;
use crate::test_wait::HANG_BOUND;

// A restart that lands while a start is discovering refuses that start: it
// must not open a login after the restart. Red today: the start captured no
// epoch, so it leads a login and answers 200.
#[tokio::test]
async fn a_start_that_discovers_across_a_restart_opens_no_login() {
    let gw = Arc::new(Gw::new().await);
    let owner = gw.session();
    let (reached, release) = gw.backend.sign_in.discovery_pause.arm();
    let start = tokio::spawn({
        let (gw, owner) = (Arc::clone(&gw), owner.clone());
        async move { gw.start(&owner).await }
    });
    crate::test_pause::within("the start reaches discovery", reached.notified()).await;
    gw.backend.login_gate.cancel_and_join().await;

    release.notify_one();
    let reply = tokio::time::timeout(HANG_BOUND, start)
        .await
        .expect("the start answers")
        .expect("the request ran");

    assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);
    assert_eq!(reply.json()["error"], "sign_in_cancelled", "{}", reply.body);
    assert!(!gw.backend.login_gate.in_flight(), "no login was opened");
}

// Discovery that outlasts the start window ends the start. Red today: nothing
// bounds it, so the start never answers.
#[tokio::test]
async fn a_discovery_past_the_start_window_ends_the_start() {
    let gw = Gw::new().await;
    gw.backend.set_sign_in_windows_for_test(windows(1, 30));
    let (_reached, _release) = gw.backend.sign_in.discovery_pause.arm();

    let reply = tokio::time::timeout(HANG_BOUND, gw.start(&gw.session()))
        .await
        .expect("the start ends at its window");

    assert_ne!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(!gw.backend.login_gate.in_flight(), "no login was opened");
}

// A start request dropped while the login registers its client discards the
// link and the attempt id, so nobody could cancel it: the login must release
// the gate on its own. Red today: the flow keeps the gate for the whole start
// window.
#[tokio::test]
async fn a_start_dropped_before_its_link_releases_the_login() {
    let gw = Arc::new(Gw::new().await);
    let serving = gw
        .backend
        .sign_in
        .installed_client
        .lock()
        .clone()
        .expect("the fixture installs a client");
    let (reached, _release) = serving.registration_pause.arm();
    let owner = gw.session();
    let start = tokio::spawn({
        let gw = Arc::clone(&gw);
        async move { gw.start(&owner).await }
    });
    crate::test_pause::within("the login reaches its registration", reached.notified()).await;

    start.abort();
    let _ = start.await;

    let began = std::time::Instant::now();
    while gw.backend.login_gate.in_flight() && began.elapsed() < HANG_BOUND {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!gw.backend.login_gate.in_flight(), "the gate is still held");
    assert!(gw.row().await["sign_in_flow"].is_null(), "the flow is gone");
}
