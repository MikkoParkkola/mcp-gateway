// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7982: a health probe never waits on a start in flight or a login,
//! and never rebuilds over one.

use super::login_window::{
    Browser, LAPSE, Upstream, approved_start, counted_authorization_server, login_backend,
    spawn_call, variant, within,
};
use super::*;

/// MIK-7982 C2: a start in flight (an interactive login waiting on the
/// browser holds the start lock for minutes) makes the probe answer at once
/// with the neutral `AuthorizationRequired`, rather than queueing behind the
/// start and then forcing a restart that would end the login.
#[tokio::test(start_paused = true)]
async fn a_health_probe_during_a_start_in_flight_does_not_wait() {
    let backend = Arc::new(Backend::new(
        "login-probe",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let entry = backend.shared_entry();
    let _start_in_flight = entry.start_lock.lock().await;

    let probe = tokio::time::timeout(
        Duration::from_millis(10),
        backend.health_probe(Duration::from_secs(5)),
    )
    .await;

    let error = probe
        .expect("a probe must not wait on a start in flight")
        .expect_err("a probe that could not look is not a pass");
    assert!(
        format!("{error:?}").starts_with("AuthorizationRequired"),
        "contention is the neutral AuthorizationRequired: {error:?}"
    );
}

/// MIK-7982 C2 (probe rebuild): a probe refused for want of a login does not
/// rebuild. On a backend with no token the probe's own start is refused
/// after one OAuth discovery; a rebuild would run a second, identical start
/// and discover again.
#[tokio::test]
async fn a_probe_refused_for_a_login_runs_one_start_and_no_rebuild() {
    let (origin, discovered) = counted_authorization_server().await;
    let dir = tempfile::tempdir().unwrap();
    let browser = Browser::new();
    let backend = login_backend(&origin, dir.path(), &browser, Duration::from_secs(30), None);

    let probed = within(
        "the probe",
        Box::pin(backend.health_probe(Duration::from_secs(5))),
    )
    .await;
    let error = probed.expect_err("no token, so the probe cannot look");
    assert!(
        variant(&error).starts_with("AuthorizationRequired"),
        "a probe that would need a login answers AuthorizationRequired: {error:?}"
    );
    let by_probe = discovered.load(Ordering::SeqCst);
    assert!(by_probe > 0, "the probe's start discovered the server");

    // What one start costs, measured the same way.
    let started = within(
        "one non-interactive start",
        crate::oauth::login_gate::non_interactive(backend.ensure_started()),
    )
    .await;
    assert!(started.is_err(), "still no token");
    let by_start = discovered.load(Ordering::SeqCst) - by_probe;

    assert_eq!(
        by_probe, by_start,
        "the probe ran its own start and then a rebuild's second one"
    );
    assert_eq!(browser.opens(), 0, "neither opens the browser");
}

/// MIK-7982 C2 (session recovery): a probe that got its token, and whose
/// request then finds its session gone, re-initializes the transport. If a
/// request-time login holds the OAuth client by then, the probe answers at
/// once instead of waiting on the login inside the re-initialization.
#[tokio::test]
async fn a_probe_recovering_its_session_does_not_wait_on_a_login() {
    // The probe sends inside the token's last 5 s; the session-expired answer
    // comes 8 s later, after another caller's login has taken the client.
    let (backend, browser, _dir) = approved_start(
        Upstream::SessionExpires(Duration::from_secs(8)),
        Duration::from_secs(30),
    )
    .await;
    let probe = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.health_probe(Duration::from_secs(25)).await })
    };
    sleep(LAPSE).await;
    let call = spawn_call(&backend);
    browser.opened(2, "the call's request-time login").await;
    assert!(
        !probe.is_finished(),
        "the login must hold the client before the probe's answer comes back"
    );

    // Ended in time, whatever it reported: the row is about not waiting.
    let _probed = tokio::time::timeout(Duration::from_secs(6), probe)
        .await
        .expect("the probe's session recovery does not wait on the login")
        .expect("probe task");
    call.abort();
}
