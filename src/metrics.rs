// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Prometheus metrics recorder installation and text-format rendering.
//!
//! Only active when compiled with the `metrics` feature (opt-in, enabled by
//! default).  Call [`install`] once at server startup; the `/metrics` handler
//! then calls [`render`] on every scrape.

#[cfg(feature = "metrics")]
use std::sync::OnceLock;

#[cfg(feature = "metrics")]
use metrics_exporter_prometheus::PrometheusHandle;

#[cfg(feature = "metrics")]
static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// The recorder's builder: buckets for the metrics that need a histogram.
/// Every other histogram keeps the exporter's default rendering.
#[cfg(feature = "metrics")]
pub(crate) fn builder() -> metrics_exporter_prometheus::PrometheusBuilder {
    use crate::gateway::health_metrics::layers::{ADDED_LATENCY, LATENCY_BUCKETS};
    use metrics_exporter_prometheus::Matcher;
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .set_buckets_for_metric(Matcher::Full(ADDED_LATENCY.to_owned()), &LATENCY_BUCKETS)
        // Fails only for an empty bucket list, which this one is not.
        .unwrap_or_else(|_| metrics_exporter_prometheus::PrometheusBuilder::new())
}

/// Install the global Prometheus metrics recorder.
///
/// Idempotent: subsequent calls are silently ignored so that test helpers
/// and server startup can both call this without panicking.
#[cfg(feature = "metrics")]
pub fn install() {
    if HANDLE.get().is_some() {
        return;
    }

    match builder().install_recorder() {
        Ok(handle) => {
            if HANDLE.set(handle).is_ok() {
                crate::gateway::health_metrics::register();
                tracing::info!("Prometheus metrics recorder installed; scrape at /metrics");
            }
        }
        Err(e) => {
            if HANDLE.get().is_none() {
                tracing::warn!(
                    error = %e,
                    "Failed to install Prometheus recorder; /metrics will return empty output"
                );
            }
        }
    }
}

/// Render the current metrics snapshot in Prometheus text exposition format.
///
/// Returns an empty string when the recorder was not installed.
#[cfg(feature = "metrics")]
pub fn render() -> String {
    HANDLE
        .get()
        .map(PrometheusHandle::render)
        .unwrap_or_default()
}
