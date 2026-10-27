// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend with per-user sessions only never opens a shared session:
//! every path to its Shared slot is refused before anything is
//! built or counted, and a backend that may share keeps sharing.

use super::*;
use crate::identity_propagation::SessionMode;

/// The refusal every shared start of a per-user-only backend answers.
fn assert_refused(result: Result<impl std::fmt::Debug>, path: &str) {
    match result {
        Err(Error::Forbidden { code, status, .. }) => {
            assert_eq!(
                (code, status),
                (-32001, 403),
                "{path}: the isolation refusal"
            );
        }
        other => panic!("{path}: a shared start was not refused: {other:?}"),
    }
}

fn shared_transport_built(backend: &Backend) -> bool {
    backend
        .pool
        .get(&PoolKey::Shared)
        .is_some_and(|entry| entry.value().transport.read().is_some())
}

/// SHARED.1: warm-start's start, an unbound fill, the probe and its rebuild,
/// and a restart are all refused, and none builds a transport.
#[tokio::test]
async fn every_shared_start_of_a_per_user_backend_is_refused() {
    let backend = per_user_backend();
    assert!(
        backend.shared_slot_refused(),
        "premise: required + per_user"
    );
    assert_refused(backend.ensure_started().await, "ensure_started");
    assert_refused(backend.warm_tools().await, "unbound fill");
    assert_refused(
        backend.health_probe(Duration::from_secs(1)).await,
        "probe and its rebuild",
    );
    assert_refused(backend.force_restart().await, "restart");
    assert!(
        !shared_transport_built(&backend),
        "a shared transport was built"
    );
    assert!(!backend.is_running());
}

/// SHARED.1: refusals are not failures. Repeated refusals, fills included,
/// leave the shared slot's breaker closed with no failure counted, no fill
/// admitted and its health untouched, so nothing escalates or trips.
#[tokio::test]
async fn a_refused_shared_start_counts_nothing() {
    let backend = per_user_backend();
    for _ in 0..5 {
        let _ = backend.ensure_started().await;
        let _ = backend.force_restart().await;
        let _ = backend.warm_tools().await;
    }
    assert_eq!(backend.list_fills(), 0, "a refused fill was admitted");
    let breaker = backend.circuit_breaker_stats();
    assert_eq!(breaker.state, crate::failsafe::CircuitState::Closed);
    assert_eq!(
        breaker.current_failures, 0,
        "a refusal counted as a failure"
    );
    assert_eq!(breaker.trips_count, 0);
    let health = backend.health_metrics();
    assert_eq!(health.consecutive_failures, 0, "a refusal hurt health");
    assert!(health.healthy);
    assert!(!backend.is_circuit_tripped());
}

/// SHARED.2: the lifecycle says per-user, never down, up or not started, so
/// the health loop's gate (`is_running() || is_circuit_tripped()`) never
/// probes it and an operator sees why there is no health data.
#[tokio::test]
async fn a_per_user_backend_reads_per_user() {
    let backend = per_user_backend();
    let _ = backend.ensure_started().await;
    assert_eq!(backend.lifecycle(), BackendLifecycle::PerUser);
    assert_eq!(backend.lifecycle().to_string(), "per_user");
    assert_eq!(
        serde_json::to_value(backend.status().lifecycle).expect("serialize"),
        serde_json::json!("per_user")
    );
    assert!(!(backend.is_running() || backend.is_circuit_tripped()));
}

/// SHARED.4: a backend that may share keeps its shared slot: `stateless`
/// sessions, or a binding that is not required.
#[test]
fn only_required_per_user_refuses_the_shared_slot() {
    for (required, session_mode, refused) in [
        (true, SessionMode::PerUser, true),
        (true, SessionMode::Stateless, false),
        (false, SessionMode::PerUser, false),
        (false, SessionMode::Stateless, false),
    ] {
        let backend = per_user_backend_with(required, session_mode);
        assert_eq!(
            backend.shared_slot_refused(),
            refused,
            "required={required} session_mode={session_mode:?}"
        );
        assert_eq!(
            backend.lifecycle() == BackendLifecycle::PerUser,
            refused,
            "required={required} session_mode={session_mode:?}"
        );
    }
}
