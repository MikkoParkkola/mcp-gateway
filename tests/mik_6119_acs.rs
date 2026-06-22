//! Acceptance-criterion test stubs for MIK-6119.
//!
//! - AC.1: MIK-6119.AC.1 AC.1: `CircuitBreaker::record_failure` accepts the failure `reason` and request `latency`, and on a Closed→Open transition the breaker captures a structured open-event carrying `backend`, `reason`, `latency_ms`, and `consecutive_fail_count` (= the failure count at trip), retrievable via a public accessor/`CircuitBreakerStats` field without parsing logs. A committed unit test trips the breaker by hitting `failure_threshold` and asserts all four fields are populated and correct. CHECK: `cargo test --lib --manifest-path /home/mikko/github/mcp-gateway/Cargo.toml circuit_breaker::tests::breaker_open_event` exits 0 (expected: `test result: ok`).
//! - AC.2: MIK-6119.AC.2 AC.2: Every Closed→Open transition emits a single structured `tracing` event AND increments a metric counter named `mcp_circuit_breaker_opened_total` labelled by `backend` and `reason`, with `latency_ms` and `consecutive_fail_count` present as event fields; the failure call site at `src/backend/mod.rs:681-683` threads the real error string and elapsed latency into `record_failure` (no hard-coded placeholder). CHECK: file `/home/mikko/github/mcp-gateway/src/failsafe/circuit_breaker.rs` matches regex `mcp_circuit_breaker_opened_total` AND file matches regex `consecutive_fail_count` (expected: both present in the Open-transition arm).
//! - AC.3: MIK-6119.AC.3 AC.3: The new telemetry adds no new Open transitions and does not change breaker thresholds — existing breaker regression tests still pass unchanged, proving the change is observability-only. CHECK: `cargo test --lib --manifest-path /home/mikko/github/mcp-gateway/Cargo.toml failsafe::circuit_breaker` exits 0 (expected: `test result: ok`, all pre-existing breaker tests green).
//! - AC.4: MIK-6119.AC.4 AC.deploy: Diff merged to `main` (target main), release binary built and deployed by the cron, and 30 min of post-deploy telemetry confirms the new `mcp_circuit_breaker_opened_total` counter is emitted in production with non-empty `reason`/`latency_ms` fields on the next breaker open (or, if no open occurs in-window, the counter is registered and queryable at the gateway edge). CHECK: `git log origin/main --grep 'MIK-6119' --oneline` exits 0 AND `rg -l 'mcp_circuit_breaker_opened_total' /home/mikko/github/mcp-gateway/src/` finds the emitting source.

/// MIK-6119.AC.1 AC.1: `CircuitBreaker::record_failure` accepts the failure `reason` and request `latency`, and on a Closed→Open transition the breaker captures a structured open-event carrying `backend`, `reason`, `latency_ms`, and `consecutive_fail_count` (= the failure count at trip), retrievable via a public accessor/`CircuitBreakerStats` field without parsing logs. A committed unit test trips the breaker by hitting `failure_threshold` and asserts all four fields are populated and correct. CHECK: `cargo test --lib --manifest-path /home/mikko/github/mcp-gateway/Cargo.toml circuit_breaker::tests::breaker_open_event` exits 0 (expected: `test result: ok`).
#[test]
fn ac_1_mik_6119_ac_1_ac_1_circuitbreaker_record_fail() {
    use mcp_gateway::failsafe::{CircuitBreaker, CircuitState};
    use mcp_gateway::config::CircuitBreakerConfig;
    use std::time::Duration;

    let cfg = CircuitBreakerConfig {
        enabled: true,
        failure_threshold: 3,
        success_threshold: 2,
        reset_timeout: Duration::from_secs(30),
    };
    let cb = CircuitBreaker::new("hebb", &cfg);

    cb.record_failure("connect timeout", Duration::from_millis(1500));
    cb.record_failure("connect timeout", Duration::from_millis(2100));
    cb.record_failure("read timeout", Duration::from_millis(5000));

    assert_eq!(cb.state(), CircuitState::Open);

    let s = cb.stats();
    assert_eq!(s.state, CircuitState::Open);
    assert_eq!(s.last_open_reason, "read timeout");
    assert_eq!(s.last_open_latency_ms, 5000);
    assert_eq!(s.current_failures, 3);
    assert_eq!(s.failure_threshold, 3);
    assert_eq!(s.trips_count, 1);
    assert_ne!(s.last_trip_ms, 0);
}

/// MIK-6119.AC.2 AC.2: Every Closed→Open transition emits a single structured `tracing` event AND increments a metric counter named `mcp_circuit_breaker_opened_total` labelled by `backend` and `reason`, with `latency_ms` and `consecutive_fail_count` present as event fields; the failure call site at `src/backend/mod.rs:681-683` threads the real error string and elapsed latency into `record_failure` (no hard-coded placeholder). CHECK: file `/home/mikko/github/mcp-gateway/src/failsafe/circuit_breaker.rs` matches regex `mcp_circuit_breaker_opened_total` AND file matches regex `consecutive_fail_count` (expected: both present in the Open-transition arm).
#[test]
fn ac_2_mik_6119_ac_2_ac_2_every_closed_open_transition() {
    let circuit_breaker_rs =
        std::fs::read_to_string("src/failsafe/circuit_breaker.rs")
            .expect("circuit_breaker.rs must exist");

    assert!(
        circuit_breaker_rs.contains("mcp_circuit_breaker_opened_total"),
        "circuit_breaker.rs must contain mcp_circuit_breaker_opened_total"
    );
    assert!(
        circuit_breaker_rs.contains("consecutive_fail_count"),
        "circuit_breaker.rs must contain consecutive_fail_count"
    );

    let backend_mod_rs =
        std::fs::read_to_string("src/backend/mod.rs")
            .expect("backend/mod.rs must exist");

    assert!(
        backend_mod_rs.contains("record_failure(&e.to_string(), latency)"),
        "backend/mod.rs must thread real error string and latency into record_failure"
    );
}

/// MIK-6119.AC.3 AC.3: The new telemetry adds no new Open transitions and does not change breaker thresholds — existing breaker regression tests still pass unchanged, proving the change is observability-only. CHECK: `cargo test --lib --manifest-path /home/mikko/github/mcp-gateway/Cargo.toml failsafe::circuit_breaker` exits 0 (expected: `test result: ok`, all pre-existing breaker tests green).
#[test]
fn ac_3_mik_6119_ac_3_ac_3_the_new_telemetry_adds_no_ne() {
    use mcp_gateway::failsafe::{CircuitBreaker, CircuitState};
    use mcp_gateway::config::CircuitBreakerConfig;
    use std::time::Duration;

    let cfg = CircuitBreakerConfig {
        enabled: true,
        failure_threshold: 3,
        success_threshold: 2,
        reset_timeout: Duration::from_secs(30),
    };
    let cb = CircuitBreaker::new("test", &cfg);

    assert!(cb.can_proceed());
    assert_eq!(cb.state(), CircuitState::Closed);

    cb.record_failure("e1", Duration::ZERO);
    cb.record_failure("e2", Duration::ZERO);
    assert_eq!(cb.state(), CircuitState::Closed);
    cb.record_failure("e3", Duration::ZERO);
    assert_eq!(cb.state(), CircuitState::Open);
    assert!(!cb.can_proceed());

    let s = cb.stats();
    assert_eq!(s.failure_threshold, 3);
    assert_eq!(s.trips_count, 1);
}

/// MIK-6119.AC.4 AC.deploy: Diff merged to `main` (target main), release binary built and deployed by the cron, and 30 min of post-deploy telemetry confirms the new `mcp_circuit_breaker_opened_total` counter is emitted in production with non-empty `reason`/`latency_ms` fields on the next breaker open (or, if no open occurs in-window, the counter is registered and queryable at the gateway edge). CHECK: `git log origin/main --grep 'MIK-6119' --oneline` exits 0 AND `rg -l 'mcp_circuit_breaker_opened_total' /home/mikko/github/mcp-gateway/src/` finds the emitting source.
#[test]
fn ac_4_mik_6119_ac_4_ac_deploy_diff_merged_to_main() {
    let circuit_breaker_rs =
        std::fs::read_to_string("src/failsafe/circuit_breaker.rs")
            .expect("circuit_breaker.rs must exist");

    assert!(
        circuit_breaker_rs.contains("mcp_circuit_breaker_opened_total"),
        "mcp_circuit_breaker_opened_total counter must be emitted in circuit_breaker.rs"
    );

    assert!(
        circuit_breaker_rs.contains("reason = %reason"),
        "reason field must be present in the Open-transition tracing event"
    );

    assert!(
        circuit_breaker_rs.contains("latency_ms = latency_ms"),
        "latency_ms field must be present in the Open-transition tracing event"
    );
}

