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
    // The start itself, not a request: the audit layer runs a handler on a
    // task of its own, which would keep the future alive after a disconnect.
    let start = tokio::spawn({
        let gw = Arc::clone(&gw);
        async move {
            super::super::signin_flow::start(&gw.state, &gw.backend, "owner".to_owned(), None).await
        }
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

// The same claim through the real POST start route. On a gateway with no audit
// log the admin layer passes a request straight through (see the layer's doc in
// `admin_audit.rs`), so a request dropped during registration drops the start
// and its guard cancels the attempt: the gate frees within the bound and no flow
// remains. With an audit log the layer runs the handler on a task of its own, so
// the start runs to completion after a disconnect and the gate frees only at the
// start window; the direct-call row above covers the guard itself.
#[tokio::test]
async fn a_dropped_start_request_releases_the_login_without_an_audit_log() {
    let gw = Arc::new(Gw::new_without_audit_log().await);
    let serving = gw
        .backend
        .sign_in
        .installed_client
        .lock()
        .clone()
        .expect("the fixture installs a client");
    let (reached, _release) = serving.registration_pause.arm();
    let owner = gw.session();
    let request = tokio::spawn({
        let gw = Arc::clone(&gw);
        async move { gw.start(&owner).await }
    });
    crate::test_pause::within("the login reaches its registration", reached.notified()).await;

    request.abort();
    let _ = request.await;

    let began = std::time::Instant::now();
    while gw.backend.login_gate.in_flight() && began.elapsed() < HANG_BOUND {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!gw.backend.login_gate.in_flight(), "the gate is still held");
    assert!(gw.row().await["sign_in_flow"].is_null(), "the flow is gone");
}

// Discovery and authorization share one start window. The clock is paused only
// once the start is parked at the top of discovery (no socket is in flight
// there), moved on by two seconds, and the start then released: the flow's
// end must still be the window counted from admission, not from the end of
// discovery. Red today: the deadline is taken after discovery.
#[tokio::test]
async fn a_slow_discovery_shortens_the_authorization_window() {
    let gw = Arc::new(Gw::new().await);
    gw.backend.set_sign_in_windows_for_test(windows(4, 30));
    let (reached, release) = gw.backend.sign_in.discovery_pause.arm();
    let owner = gw.session();
    let t0 = crate::clock::unix_secs().expect("a readable clock");
    let clock = crate::clock::test_clock::at_secs(t0);
    tokio::time::pause();
    let admitted = tokio::time::Instant::now();
    let start = tokio::spawn({
        let gw = Arc::clone(&gw);
        async move { gw.start(&owner).await }
    });
    crate::test_pause::within("the start reaches discovery", reached.notified()).await;

    tokio::time::advance(Duration::from_secs(2)).await;
    drop(clock);
    let _later = crate::clock::test_clock::at_secs(t0 + 2);
    release.notify_one();
    let reply = tokio::time::timeout(HANG_BOUND, start)
        .await
        .expect("the start answers")
        .expect("the request ran");

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    // The promised end the answer carries is also counted from admission.
    let ends = chrono::DateTime::parse_from_rfc3339(reply.json()["expires_at"].as_str().unwrap())
        .expect("expires_at is RFC 3339")
        .timestamp();
    assert!(
        ends <= i64::try_from(t0).unwrap() + 4,
        "expires_at runs from admission: {ends} against {t0}"
    );
    let until = gw
        .backend
        .with_flow(|slot| slot.as_ref().map(|flow| flow.until))
        .expect("the flow is pending");
    assert!(
        until <= admitted + Duration::from_secs(4) + Duration::from_millis(500),
        "the window runs from admission: {:?} past it",
        until.saturating_duration_since(admitted)
    );
}
