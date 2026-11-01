// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The layers that record the gateway's health metrics, the samples they
//! take, and the metrics' registration (help text).

use std::sync::Arc;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

use super::clock::Clock;
use super::{ErrorKind, RpcError, error_kind};

/// The histogram of the gateway's own share of a call.
pub(crate) const ADDED_LATENCY: &str = "mcp_gateway_added_latency_seconds";

/// The counter of errors clients received, by kind.
pub(crate) const ERRORS: &str = "mcp_gateway_errors_total";

#[cfg(feature = "metrics")]
/// Upper bounds of `ADDED_LATENCY`'s buckets, in seconds.
pub(crate) const LATENCY_BUCKETS: [f64; 11] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
];

/// On a response whose own stream records its latency and its error, so
/// neither layer records it again.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamAccounted;

impl ErrorKind {
    /// The `kind` label value.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Request => "request",
            Self::Internal => "internal",
            Self::Backend => "backend",
        }
    }

    #[cfg(feature = "metrics")]
    const ALL: [Self; 4] = [Self::Auth, Self::Request, Self::Internal, Self::Backend];
}

/// Count one error of `kind` that a client received.
pub(crate) fn count_error(kind: ErrorKind) {
    telemetry_metrics::counter!(ERRORS, "kind" => kind.label()).increment(1);
}

/// Count the answer with `status` and `marker`, if it is an error.
pub(crate) fn count_answer(status: u16, marker: Option<RpcError>) {
    if let Some(kind) = error_kind(status, marker) {
        count_error(kind);
    }
}

/// Count the answer a stream framed as its last event: the substituted
/// internal-error frame is an internal error whatever the answer was.
pub(crate) fn count_framed(status: u16, marker: Option<RpcError>, substituted: bool) {
    if substituted {
        count_error(ErrorKind::Internal);
    } else {
        count_answer(status, marker);
    }
}

/// One latency sample, taken once: when asked, or on drop if never asked, so
/// a client that goes away mid-call still leaves its sample.
pub(crate) struct Sample(Option<Arc<Clock>>);

impl Sample {
    pub(crate) fn of(clock: Option<Arc<Clock>>) -> Self {
        Self(clock)
    }

    /// Record now; later calls and the drop record nothing.
    pub(crate) fn record(&mut self) {
        if let Some(clock) = self.0.take() {
            telemetry_metrics::histogram!(ADDED_LATENCY).record(clock.added().as_secs_f64());
        }
    }

    /// Give up the sample: something else records it.
    pub(crate) fn forget(&mut self) {
        self.0 = None;
    }
}

impl Drop for Sample {
    fn drop(&mut self) {
        self.record();
    }
}

/// Times a `POST /mcp` request: opens its clock, and records the whole time
/// minus the backend waits when the response returns (or on drop).
pub(crate) async fn latency_layer(request: Request, next: Next) -> Response {
    let clock = Clock::start();
    let mut sample = Sample::of(Some(Arc::clone(&clock)));
    let response = clock.scope(next.run(request)).await;
    if response.extensions().get::<StreamAccounted>().is_some() {
        sample.forget();
    }
    response
}

/// Counts the error, if any, the client receives, once per answer, from the
/// final status and marker. A stream counts its own.
pub(crate) async fn error_layer(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    if response.extensions().get::<StreamAccounted>().is_none() {
        let marker = response.extensions().get::<RpcError>().copied();
        count_answer(response.status().as_u16(), marker);
    }
    response
}

/// Help text for every health metric.
#[cfg(feature = "metrics")]
pub(crate) fn register() {
    telemetry_metrics::describe_histogram!(
        ADDED_LATENCY,
        telemetry_metrics::Unit::Seconds,
        "Time the gateway added to a POST /mcp call: the whole request time minus the time it \
         waited on backend transports. Retries and backoff inside a transport count as backend \
         wait, as does waiting on another reader's catalogue fill; the gateway's own admission, \
         semaphore wait and retry backoff count as added latency."
    );
    telemetry_metrics::describe_counter!(
        ERRORS,
        "Errors a client received from the gateway, by kind (auth, request, internal, backend). \
         Backend means a backend's own error answer or a backend failure the gateway reports \
         (timeout, unavailable, circuit open, transport); the gateway's own refusals, rate \
         limits included, are not. This is the client-received view. mcp_backend_requests_total is the backend-side view: \
         it does not count circuit-open refusals before dispatch and counts forwarded JSON-RPC \
         errors as status=ok. mcp_jsonrpc_requests_total{status=error} counts JSON-RPC errors \
         on /mcp only. A tool result with isError: true is not an error here."
    );
    // Zero series, so a dashboard sees every kind before the first error.
    for kind in ErrorKind::ALL {
        telemetry_metrics::counter!(ERRORS, "kind" => kind.label()).increment(0);
    }
}
