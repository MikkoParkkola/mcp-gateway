// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `backends_overall_healthy` predicate cases, split out of `handlers.rs`
//! to keep that file under the line-count ceiling.
use super::backends_overall_healthy;
use crate::backend::BackendStatus;
use crate::failsafe::CircuitState;
use std::collections::HashMap;

fn status(name: &str, circuit: CircuitState, healthy: bool) -> BackendStatus {
    BackendStatus {
        name: name.to_string(),
        running: true,
        lifecycle: crate::backend::BackendLifecycle::Running,
        transport: "http".to_string(),
        tools_cached: 0,
        tools_known: true,
        circuit_state: circuit,
        request_count: 0,
        healthy,
        consecutive_failures: if healthy { 0 } else { 3 },
        latency_p95_ms: None,
        runtime: None,
    }
}

fn map(items: Vec<BackendStatus>) -> HashMap<String, BackendStatus> {
    items.into_iter().map(|s| (s.name.clone(), s)).collect()
}

#[test]
fn all_healthy_is_healthy() {
    let m = map(vec![
        status("a", CircuitState::Closed, true),
        status("b", CircuitState::Closed, true),
    ]);
    assert!(backends_overall_healthy(&m));
}

#[test]
fn open_circuit_is_unhealthy() {
    let m = map(vec![
        status("a", CircuitState::Closed, true),
        status("b", CircuitState::Open, true),
    ]);
    assert!(!backends_overall_healthy(&m));
}

#[test]
fn tracker_unhealthy_with_closed_circuit_is_unhealthy() {
    // MIK-5080: a backend timing out under load flips the health tracker
    // unhealthy before the circuit breaker trips Open. /health must catch it.
    let m = map(vec![
        status("a", CircuitState::Closed, true),
        status("b", CircuitState::Closed, false),
    ]);
    assert!(!backends_overall_healthy(&m));
}

/// Only `Open` degrades: a half-open breaker is letting trial requests through.
#[test]
fn half_open_circuit_is_healthy() {
    let m = map(vec![status("a", CircuitState::HalfOpen, true)]);
    assert!(backends_overall_healthy(&m));
}
