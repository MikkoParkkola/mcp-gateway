// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Proves `mcp_backend_idle_stop_close_failures` (src/backend/pool.rs)
//! actually reaches the Prometheus text-exposition output produced by
//! `mcp_gateway::metrics::render()` -- the claim docs/DEPLOYMENT.md's
//! alerting section rests on, previously backed only by reading the code.
//!
//! Isolated in its own integration test binary on purpose:
//! `metrics_exporter_prometheus::PrometheusBuilder::install_recorder` installs
//! a PROCESS-GLOBAL recorder behind a `OnceLock` (src/metrics.rs `HANDLE`).
//! A second test in the same binary calling `install()`/`render()` would
//! share that global state and race on it. Run only this binary:
//!   cargo test --features metrics --test metrics_export_test

#![cfg(feature = "metrics")]

#[test]
fn idle_stop_close_failure_counter_reaches_metrics_render() {
    mcp_gateway::metrics::install();

    // Baseline: before this specific counter/label pair is ever incremented,
    // the metric name must not already be present -- otherwise the assertion
    // below would pass for a reason unrelated to the increment.
    let before = mcp_gateway::metrics::render();
    assert!(
        !before.contains("mcp_backend_idle_stop_close_failures"),
        "metric name present before any increment; test would not be proving \
         anything. Rendered output:\n{before}"
    );

    telemetry_metrics::counter!(
        "mcp_backend_idle_stop_close_failures",
        "backend" => "test-backend"
    )
    .increment(1);

    let after = mcp_gateway::metrics::render();

    assert!(
        after.contains("mcp_backend_idle_stop_close_failures"),
        "expected mcp_backend_idle_stop_close_failures in rendered output \
         after increment, got:\n{after}"
    );
    assert!(
        after.contains("backend=\"test-backend\""),
        "expected the backend label to survive to the rendered output, got:\n{after}"
    );
}
