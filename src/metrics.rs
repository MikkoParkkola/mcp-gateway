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

/// Install the global Prometheus metrics recorder.
///
/// Idempotent: subsequent calls are silently ignored so that test helpers
/// and server startup can both call this without panicking.
#[cfg(feature = "metrics")]
pub fn install() {
    if HANDLE.get().is_some() {
        return;
    }

    match metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder() {
        Ok(handle) => {
            if HANDLE.set(handle).is_ok() {
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

/// One metric labelled by `backend`, built and retained once.
///
/// The `gauge!`/`counter!`/`histogram!` macros rebuild their key on every
/// write: a label `String`, a label `Vec`, a hash, and the Prometheus
/// recorder's own retained copy. On the per-request path that cost lands on
/// every `tools/call` (NFR.WORKLOAD.1). A retained key clones by reference
/// count. Each write still resolves the recorder current at that moment, as
/// the macros do, so a test's local recorder sees the same series.
#[derive(Clone, Debug)]
pub(crate) struct BackendMetric(telemetry_metrics::Key);

/// What the macros would pass from here; every recorder in the tree ignores it.
static METADATA: telemetry_metrics::Metadata<'static> = telemetry_metrics::Metadata::new(
    module_path!(),
    telemetry_metrics::Level::INFO,
    Some(module_path!()),
);

impl BackendMetric {
    /// `name{backend, extra...}`, labels in the order the macros used.
    fn new(name: &'static str, backend: &str, extra: &[(&'static str, &'static str)]) -> Self {
        let labels = std::iter::once(telemetry_metrics::Label::new("backend", backend.to_owned()))
            .chain(
                extra
                    .iter()
                    .map(|&(k, v)| telemetry_metrics::Label::from_static_parts(k, v)),
            )
            .collect::<Vec<_>>();
        Self(telemetry_metrics::Key::from_parts(name, labels).to_retained())
    }

    pub(crate) fn gauge(&self) -> telemetry_metrics::Gauge {
        telemetry_metrics::with_recorder(|r| r.register_gauge(&self.0, &METADATA))
    }

    pub(crate) fn counter(&self) -> telemetry_metrics::Counter {
        telemetry_metrics::with_recorder(|r| r.register_counter(&self.0, &METADATA))
    }

    pub(crate) fn histogram(&self) -> telemetry_metrics::Histogram {
        telemetry_metrics::with_recorder(|r| r.register_histogram(&self.0, &METADATA))
    }
}

/// The per-request series of one backend, keyed once per slot.
#[derive(Clone, Debug)]
pub(crate) struct BackendMetrics {
    backend: String,
    /// `mcp_backend_circuit_state{backend}`.
    pub(crate) circuit_state: BackendMetric,
    /// `mcp_backend_requests_total{backend, status="ok"}`.
    pub(crate) requests_ok: BackendMetric,
    /// `mcp_backend_requests_total{backend, status="rate_limited"}`.
    pub(crate) requests_rate_limited: BackendMetric,
    /// `mcp_backend_request_duration_seconds{backend}`.
    pub(crate) request_duration: BackendMetric,
}

impl BackendMetrics {
    pub(crate) fn new(backend: &str) -> Self {
        let requests = |status| {
            BackendMetric::new("mcp_backend_requests_total", backend, &[("status", status)])
        };
        Self {
            backend: backend.to_owned(),
            circuit_state: BackendMetric::new("mcp_backend_circuit_state", backend, &[]),
            requests_ok: requests("ok"),
            requests_rate_limited: requests("rate_limited"),
            request_duration: BackendMetric::new(
                "mcp_backend_request_duration_seconds",
                backend,
                &[],
            ),
        }
    }

    /// Whether these keys carry `backend` as their label.
    pub(crate) fn is_for(&self, backend: &str) -> bool {
        self.backend == backend
    }
}
