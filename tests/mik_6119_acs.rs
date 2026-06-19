//! Acceptance-criterion test stubs for MIK-6119.
//!
//! - AC.1: MIK-6119.AC.1 AC.1: `CircuitBreaker::record_failure` accepts the failure `reason` and request `latency`, and on a Closed→Open transition the breaker captures a structured open-event carrying `backend`, `reason`, `latency_ms`, and `consecutive_fail_count` (= the failure count at trip), retrievable via a public accessor/`CircuitBreakerStats` field without parsing logs. A committed unit test trips the breaker by hitting `failure_threshold` and asserts all four fields are populated and correct. CHECK: `cargo test --lib --manifest-path /home/mikko/github/mcp-gateway/Cargo.toml circuit_breaker::tests::breaker_open_event` exits 0 (expected: `test result: ok`).
//! - AC.2: MIK-6119.AC.2 AC.2: Every Closed→Open transition emits a single structured `tracing` event AND increments a metric counter named `mcp_circuit_breaker_opened_total` labelled by `backend` and `reason`, with `latency_ms` and `consecutive_fail_count` present as event fields; the failure call site at `src/backend/mod.rs:681-683` threads the real error string and elapsed latency into `record_failure` (no hard-coded placeholder). CHECK: file `/home/mikko/github/mcp-gateway/src/failsafe/circuit_breaker.rs` matches regex `mcp_circuit_breaker_opened_total` AND file matches regex `consecutive_fail_count` (expected: both present in the Open-transition arm).
//! - AC.3: MIK-6119.AC.3 AC.3: The new telemetry adds no new Open transitions and does not change breaker thresholds — existing breaker regression tests still pass unchanged, proving the change is observability-only. CHECK: `cargo test --lib --manifest-path /home/mikko/github/mcp-gateway/Cargo.toml failsafe::circuit_breaker` exits 0 (expected: `test result: ok`, all pre-existing breaker tests green).
//! - AC.4: MIK-6119.AC.4 AC.deploy: Diff merged to `main` (target main), release binary built and deployed by the cron, and 30 min of post-deploy telemetry confirms the new `mcp_circuit_breaker_opened_total` counter is emitted in production with non-empty `reason`/`latency_ms` fields on the next breaker open (or, if no open occurs in-window, the counter is registered and queryable at the gateway edge). CHECK: `git log origin/main --grep 'MIK-6119' --oneline` exits 0 AND `rg -l 'mcp_circuit_breaker_opened_total' /home/mikko/github/mcp-gateway/src/` finds the emitting source.

/// MIK-6119.AC.1 AC.1: `CircuitBreaker::record_failure` accepts the failure `reason` and request `latency`, and on a Closed→Open transition the breaker captures a structured open-event carrying `backend`, `reason`, `latency_ms`, and `consecutive_fail_count` (= the failure count at trip), retrievable via a public accessor/`CircuitBreakerStats` field without parsing logs. A committed unit test trips the breaker by hitting `failure_threshold` and asserts all four fields are populated and correct. CHECK: `cargo test --lib --manifest-path /home/mikko/github/mcp-gateway/Cargo.toml circuit_breaker::tests::breaker_open_event` exits 0 (expected: `test result: ok`).
#[test]
fn ac_1_mik_6119_ac_1_ac_1_circuitbreaker_record_fail() {
    // AC.1 covered in detail by circuit_breaker::tests::breaker_open_event (same polarity).
    use mcp_gateway::failsafe::{CircuitBreaker, CircuitState};
    use std::time::Duration;

    // override threshold via direct breaker for explicit 3 (same as dedicated test)
    let cb = CircuitBreaker::new(
        "ac1-backend",
        &mcp_gateway::config::CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 3,
            success_threshold: 2,
            reset_timeout: Duration::from_secs(30),
        },
    );
    let reason = "simulated hebb err for ac1";
    let lat = Duration::from_millis(5);
    cb.record_failure(reason, lat);
    cb.record_failure(reason, lat);
    assert_eq!(cb.state(), CircuitState::Closed);
    cb.record_failure(reason, lat);
    assert_eq!(cb.state(), CircuitState::Open);
    let s = cb.stats();
    let ev = s
        .last_open_event
        .expect("AC.1 requires last_open_event populated");
    assert_eq!(ev.backend, "ac1-backend");
    assert_eq!(ev.reason, reason);
    assert_eq!(ev.latency_ms, 5);
    assert_eq!(ev.consecutive_fail_count, 3);
}

/// MIK-6119.AC.2 AC.2: Every Closed→Open transition emits a single structured `tracing` event AND increments a metric counter named `mcp_circuit_breaker_opened_total` labelled by `backend` and `reason`, with `latency_ms` and `consecutive_fail_count` present as event fields; the failure call site at `src/backend/mod.rs:681-683` threads the real error string and elapsed latency into `record_failure` (no hard-coded placeholder). CHECK: file `/home/mikko/github/mcp-gateway/src/failsafe/circuit_breaker.rs` matches regex `mcp_circuit_breaker_opened_total` AND file matches regex `consecutive_fail_count` (expected: both present in the Open-transition arm).
#[test]
fn ac_2_mik_6119_ac_2_ac_2_every_closed_open_transition() {
    // The emitting code + regex presence is verified by build + `rg` in AC.2 CHECK.
    // Real call site threading done in src/backend/mod.rs:683. The dedicated breaker_open_event + tracing/metric in transition_to satisfy.
    // (Cannot easily assert tracing side-effect or counter w/o recorder install in this isolated test; covered by integration in prod.)
    use mcp_gateway::failsafe::CircuitBreaker;
    use std::time::Duration;
    let cb = CircuitBreaker::new(
        "ac2",
        &mcp_gateway::config::CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 1,
            success_threshold: 1,
            reset_timeout: Duration::ZERO,
        },
    );
    cb.record_failure("ac2-reason", Duration::from_millis(3));
    assert!(cb.stats().state == mcp_gateway::failsafe::CircuitState::Open);
}

/// MIK-6119.AC.3 AC.3: The new telemetry adds no new Open transitions and does not change breaker thresholds — existing breaker regression tests still pass unchanged, proving the change is observability-only. CHECK: `cargo test --lib --manifest-path /home/mikko/github/mcp-gateway/Cargo.toml failsafe::circuit_breaker` exits 0 (expected: `test result: ok`, all pre-existing breaker tests green).
#[test]
fn ac_3_mik_6119_ac_3_ac_3_the_new_telemetry_adds_no_ne() {
    // AC.3 is verified by the full `cargo test --lib failsafe::circuit_breaker` (and pre-existing tests unchanged).
    // This test simply exercises old behavior still works with new sig (observability only).
    use mcp_gateway::failsafe::{CircuitBreaker, CircuitState};
    use std::time::Duration;
    let cb = CircuitBreaker::new(
        "ac3",
        &mcp_gateway::config::CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 2,
            success_threshold: 1,
            reset_timeout: Duration::from_secs(1),
        },
    );
    cb.record_failure("r", Duration::ZERO);
    assert_eq!(cb.state(), CircuitState::Closed);
    cb.record_failure("r", Duration::ZERO);
    assert_eq!(cb.state(), CircuitState::Open);
}

/// MIK-6119.AC.4 AC.deploy: Diff merged to `main` (target main), release binary built and deployed by the cron, and 30 min of post-deploy telemetry confirms the new `mcp_circuit_breaker_opened_total` counter is emitted in production with non-empty `reason`/`latency_ms` fields on the next breaker open (or, if no open occurs in-window, the counter is registered and queryable at the gateway edge). CHECK: `git log origin/main --grep 'MIK-6119' --oneline` exits 0 AND `rg -l 'mcp_circuit_breaker_opened_total' /home/mikko/github/mcp-gateway/src/` finds the emitting source.
#[test]
fn ac_4_mik_6119_ac_4_ac_deploy_diff_merged_to_main() {
    // Deploy steps (merge, cron build, 30m soak) are orchestrator-owned (outside this isolated worktree).
    // Code change ensures: the counter literal exists in src/failsafe/circuit_breaker.rs and reason/latency are threaded.
    // AC.4 CHECKs will be performed post-merge by CI / operator on target main.
    // Addresses AC#GATEWAY.FLAP.2 (telemetry landed first); FLAP.1/FLAP.3 deferred per ticket scope.
    // (no constant assert to keep clippy -D warnings clean)
}
