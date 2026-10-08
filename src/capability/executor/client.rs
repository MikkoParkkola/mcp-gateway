// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The executor's HTTP client: direct and pinned, or through the operator's
//! `capabilities.egress_proxy` (#1881).

use std::time::Duration;

use reqwest::Client;

use crate::security::validate_url_not_ssrf;
use crate::{Error, Result};

/// Build a pooled HTTP client suitable for capability execution.
///
/// Matches the pooling parameters used by `HttpTransport` so all outbound HTTP
/// shares the same connection-management strategy and avoids per-request FD
/// creation.
///
/// With no `proxy`, every name is resolved once and pinned (MIK-4019) and
/// `HTTP(S)_PROXY` from the environment is ignored, since a proxy would
/// resolve the name instead of the pin. With a `proxy`, every call goes to it
/// and the proxy resolves destinations: the pin is not installed, because it
/// would refuse the proxy itself on the private address a proxy normally has.
/// Each redirect hop is literal-checked either way.
///
/// # Panics
///
/// Panics if the reqwest client cannot be created (invalid TLS config, etc.).
pub(super) fn build(proxy: Option<&url::Url>) -> Client {
    route(proxy)
        .timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 {
                return attempt.stop();
            }
            if let Err(e) = validate_url_not_ssrf(attempt.url().as_str()) {
                return attempt.error(e.to_string());
            }
            // A 307/308 re-sends the body and every header but `Authorization`,
            // so a request that started on TLS or loopback (where a credential
            // may go) never continues in cleartext off this machine (#3013).
            let started_secure = attempt
                .previous()
                .first()
                .is_some_and(crate::gateway::is_tls_or_loopback);
            if started_secure && !crate::gateway::is_tls_or_loopback(attempt.url()) {
                return attempt
                    .error("refusing a capability redirect to cleartext http:// off this machine");
            }
            attempt.follow()
        }))
        .build()
        .expect("Failed to create HTTP client")
}

/// The route of every capability call: pinned and direct, or through
/// `proxy`.
fn route(proxy: Option<&url::Url>) -> reqwest::ClientBuilder {
    match proxy {
        None => crate::security::ssrf::pinned_client_builder(),
        // Loopback goes direct: cleartext to it is allowed only because it
        // stays on the machine, and the proxy would carry it off (#3013).
        Some(url) => Client::builder().no_proxy().proxy(
            reqwest::Proxy::all(url.as_str())
                .expect("capabilities.egress_proxy validated at load")
                .no_proxy(reqwest::NoProxy::from_string("localhost,127.0.0.0/8,::1")),
        ),
    }
}

/// The client a provider's OAuth refresh goes through (MIK-8020): the route
/// of [`build`], with redirects off, so a refresh token is never re-sent to a
/// redirect target and a connect error proves nothing was sent.
#[derive(Clone)]
pub(super) struct RefreshClient {
    pub(super) http: Client,
    /// The policy the route enforces, for typing a refused redirect target.
    pub(super) destination: crate::security::ssrf::DestinationPolicy,
}

/// [`RefreshClient`] for `proxy`. Its 30 s request timeout stays under the
/// refresh exchange's own bound.
///
/// # Panics
///
/// Panics if the reqwest client cannot be created, as [`build`] does.
pub(super) fn build_refresh(proxy: Option<&url::Url>) -> RefreshClient {
    use crate::security::ssrf::DestinationPolicy;
    RefreshClient {
        http: route(proxy)
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to create HTTP client"),
        destination: if proxy.is_some() {
            DestinationPolicy::Configured
        } else {
            DestinationPolicy::Public
        },
    }
}

/// Maximum number of send attempts (1 initial + 2 retries) for transient
/// outbound transport failures.
pub(super) const MAX_SEND_ATTEMPTS: u32 = 3;

/// Send an outbound HTTP request, retrying transient transport failures with
/// exponential backoff, and recording the transport outcome on `health`.
///
/// Capability calls run inside the gateway's own tokio runtime, so a transient
/// connect failure reaching an upstream (e.g. a momentary blip reaching
/// `api.linear.app` under host load) otherwise surfaces directly as a
/// `BACKEND_ERROR` to the caller (MIK-5081).
///
/// Retry policy:
/// - **Connection** failures are always retried — no request bytes were sent,
///   so a retry is side-effect-free.
/// - **Timeout** failures are retried only when `retry_timeouts` is true (i.e.
///   the request is idempotent). A timeout on a non-idempotent POST may mean
///   the upstream already processed it, so blindly replaying it could duplicate
///   a side effect.
/// - HTTP error *statuses* (4xx/5xx) are returned unchanged (never retried) and
///   count as a live backend for health purposes.
///
/// Health: a transport success (any HTTP status) records success; exhausting
/// retries records a failure. The request is cloned per attempt; a
/// non-cloneable body is sent once.
/// Render an outbound transport error without the URL it was built from.
///
/// `reqwest::Error`'s `Display` appends `" for url (...)"` verbatim
/// (`reqwest-0.13.4/src/error.rs:279-280`), and reqwest's own docs on
/// [`reqwest::Error::without_url`] warn that the URL may carry a credential.
/// Backend URLs here are operator-configured and a query-string API key is a
/// common shape, so the raw error must never reach a log sink or a client.
pub(super) fn redact_url(e: reqwest::Error) -> reqwest::Error {
    e.without_url()
}

pub(super) async fn send_with_retry(
    request: reqwest::RequestBuilder,
    label: &str,
    retry_timeouts: bool,
    health: &crate::failsafe::HealthTracker,
) -> Result<reqwest::Response> {
    let started = std::time::Instant::now();
    let mut backoff_ms: u64 = 100;
    for attempt in 1..=MAX_SEND_ATTEMPTS {
        let Some(attempt_req) = request.try_clone() else {
            // Non-cloneable body: a single attempt is the best we can do.
            return match request.send().await {
                Ok(resp) => {
                    health.record_success(started.elapsed());
                    Ok(resp)
                }
                Err(e) => Err(
                    crate::security::http_diagnostics::ssrf_refusal(&e).unwrap_or_else(|| {
                        health.record_failure();
                        Error::Transport(format!("{label} failed: {}", redact_url(e)))
                    }),
                ),
            };
        };
        match attempt_req.send().await {
            Ok(resp) => {
                health.record_success(started.elapsed());
                return Ok(resp);
            }
            Err(e) => {
                // A refused destination is refused again: one attempt, no health mark.
                if let Some(refused) = crate::security::http_diagnostics::ssrf_refusal(&e) {
                    return Err(refused);
                }
                let transient = e.is_connect() || (retry_timeouts && e.is_timeout());
                let e = redact_url(e);
                if transient && attempt < MAX_SEND_ATTEMPTS {
                    tracing::warn!(
                        label = label,
                        attempt = attempt,
                        backoff_ms = backoff_ms,
                        error = %e,
                        "transient outbound transport error; retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    backoff_ms *= 2;
                    continue;
                }
                health.record_failure();
                return Err(Error::Transport(format!("{label} failed: {e}")));
            }
        }
    }
    // The final attempt always returns above; the loop cannot fall through.
    unreachable!("send_with_retry exhausted attempts without returning")
}
