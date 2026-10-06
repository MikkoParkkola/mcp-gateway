// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7982: a health probe never waits on a start in flight.

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
