// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8014 PERF.13 step (a): `mcp_unkeyed_calls_total` is counted on every
//! un-keyed admission. With computed label values the metrics macro builds a
//! label `Vec` and a `Key` on every call; with literal labels it uses a static
//! key. These rows pin that the count allocates nothing and that the exported
//! series are unchanged.

use std::sync::Arc;

/// Legacy only: a modern call also runs the warn limiter, whose own work is
/// not this site's; the counter line is shared by both eras. Red on base: the
/// label values are computed, so the macro allocates a label Vec per call.
#[test]
fn an_unkeyed_admission_is_counted_without_allocating() {
    let _guard = telemetry_metrics::set_default_local_recorder(&telemetry_metrics::NoopRecorder);
    let meta = super::MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    let ((), measured) =
        crate::gateway::alloc_meter::measure(|| meta.record_unkeyed(false, false, ("b", "t")));
    assert_eq!(
        measured.calls, 0,
        "counting an un-keyed admission allocated {} times ({} B) (MIK-8014 PERF.13a)",
        measured.calls, measured.bytes
    );
}

/// Every (era, read-only) arm, measured at the helper itself: the modern arms
/// cannot be measured through `record_unkeyed`, whose warn limiter does its
/// own work. A computed label in any one arm allocates a label Vec and fails here.
#[test]
fn every_label_arm_counts_without_allocating() {
    let _guard = telemetry_metrics::set_default_local_recorder(&telemetry_metrics::NoopRecorder);
    for (is_modern, read_only) in [(true, true), (true, false), (false, true), (false, false)] {
        let ((), measured) = crate::gateway::alloc_meter::measure(|| {
            super::super::warn_limit::count_unkeyed(is_modern, read_only)
        });
        assert_eq!(
            measured.calls, 0,
            "the (modern={is_modern}, read_only={read_only}) arm allocated {} times ({} B) (MIK-8014 PERF.13a)",
            measured.calls, measured.bytes
        );
    }
}

/// Green on base and head: the series' name, labels and values are the
/// contract ADR-012 names; this is the differential check.
#[test]
fn the_unkeyed_series_render_as_before() {
    fn series(handle: &metrics_exporter_prometheus::PrometheusHandle) -> Vec<String> {
        let mut lines: Vec<String> = handle
            .render()
            .lines()
            .filter(|line| line.starts_with("mcp_unkeyed_calls_total{"))
            .map(|line| line.trim().to_string())
            .collect();
        // The exporter renders series in hash-map order, so only the order is normalised.
        lines.sort();
        lines
    }

    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _guard = telemetry_metrics::set_default_local_recorder(&recorder);
    let meta = super::MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    for _ in 0..3 {
        meta.record_unkeyed(true, false, ("b", "t"));
    }
    for _ in 0..2 {
        meta.record_unkeyed(false, false, ("b", "t"));
    }
    meta.record_unkeyed(true, true, ("b", "t"));
    assert_eq!(
        series(&handle),
        vec![
            "mcp_unkeyed_calls_total{era=\"legacy\",gateway_read_only=\"false\"} 2".to_string(),
            "mcp_unkeyed_calls_total{era=\"modern\",gateway_read_only=\"false\"} 3".to_string(),
            "mcp_unkeyed_calls_total{era=\"modern\",gateway_read_only=\"true\"} 1".to_string(),
        ],
        "three label sets used, three series, and no zero-valued fourth: {}",
        handle.render()
    );
    meta.record_unkeyed(false, true, ("b", "t"));
    assert_eq!(
        series(&handle),
        vec![
            "mcp_unkeyed_calls_total{era=\"legacy\",gateway_read_only=\"false\"} 2".to_string(),
            "mcp_unkeyed_calls_total{era=\"legacy\",gateway_read_only=\"true\"} 1".to_string(),
            "mcp_unkeyed_calls_total{era=\"modern\",gateway_read_only=\"false\"} 3".to_string(),
            "mcp_unkeyed_calls_total{era=\"modern\",gateway_read_only=\"true\"} 1".to_string(),
        ],
        "the fourth label set appears only once used: {}",
        handle.render()
    );
}
