// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The executor's HTTP client: direct and pinned, or through the operator's
//! `capabilities.egress_proxy` (#1881).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use reqwest::Client;

use crate::counters::End;
use crate::gateway::SendTimer;
use crate::security::RedirectEvidence;
use crate::security::ssrf::{RedirectDecision, redirect_decision};
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
pub(super) fn build(proxy: Option<&url::Url>) -> CapabilityClient {
    let redirects = Arc::new(AtomicU64::new(0));
    let http = http_client(proxy, Arc::clone(&redirects));
    CapabilityClient { http, redirects }
}

/// The reqwest client [`build`] wraps, its redirect policy counting each
/// redirect response into `seen`.
fn http_client(proxy: Option<&url::Url>, seen: Arc<AtomicU64>) -> Client {
    route(proxy)
        .timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            // A response came back, whether this hop is followed or refused.
            seen.fetch_add(1, Ordering::SeqCst);
            // A 307/308 re-sends the body and every header but `Authorization`,
            // so a request that started on TLS or loopback (where a credential
            // may go) never continues in cleartext off this machine (#3013).
            let started_secure = attempt
                .previous()
                .first()
                .is_some_and(crate::gateway::is_tls_or_loopback);
            // A hop naming loopback is refused by the target's own check:
            // with a proxy set it would otherwise go direct, unpinned.
            if let Err(Error::Protocol(reason)) =
                crate::security::ssrf::refuse_loopback_name(attempt.url().as_str())
            {
                return crate::security::ssrf::refuse_hop(attempt, reason);
            }
            match redirect_decision(attempt.previous().len(), attempt.url().as_str()) {
                RedirectDecision::Stop => attempt.stop(),
                RedirectDecision::Reject(msg) => crate::security::ssrf::refuse_hop(attempt, msg),
                RedirectDecision::Follow
                    if started_secure && !crate::gateway::is_tls_or_loopback(attempt.url()) =>
                {
                    attempt.error(
                        "refusing a capability redirect to cleartext http:// off this machine",
                    )
                }
                RedirectDecision::Follow => attempt.follow(),
            }
        }))
        .build()
        .expect("Failed to create HTTP client")
}

/// A capability HTTP client and the redirect responses it has received, so a
/// send can tell whether its own request may have followed one. The count is
/// per client, shared by concurrent calls: a refusal is discarded only when
/// the count did not move across its attempt, so a concurrent call's redirect
/// can at worst add a Failed sample, never drop a real one. (The MCP HTTP
/// transport keeps the same kind of counter for its retry evidence.)
#[derive(Debug, Clone)]
pub(crate) struct CapabilityClient {
    pub(super) http: Client,
    pub(super) redirects: Arc<AtomicU64>,
}

impl CapabilityClient {
    /// `http`, counting nothing: a test client with its own redirect policy.
    #[cfg(test)]
    pub(super) fn uncounted(http: Client) -> Self {
        Self {
            http,
            redirects: Arc::default(),
        }
    }
}

impl std::ops::Deref for CapabilityClient {
    type Target = Client;

    fn deref(&self) -> &Client {
        &self.http
    }
}

/// The route of every capability call: pinned and direct, or through
/// `proxy`.
fn route(proxy: Option<&url::Url>) -> reqwest::ClientBuilder {
    match proxy {
        None => crate::security::ssrf::pinned_client_builder(),
        // Loopback goes direct: cleartext to it is allowed only because it
        // stays on the machine, and the proxy would carry it off (#3013).
        // Only the literals: a loopback name is refused before any send,
        // and one a check missed reaches the proxy, never this unpinned
        // direct path.
        Some(url) => Client::builder().no_proxy().proxy(
            reqwest::Proxy::all(url.as_str())
                .expect("capabilities.egress_proxy validated at load")
                .no_proxy(reqwest::NoProxy::from_string("127.0.0.0/8,::1")),
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
    redirects: &AtomicU64,
    label: &str,
    retry_timeouts: bool,
    health: &crate::failsafe::HealthTracker,
) -> Result<reqwest::Response> {
    let started = std::time::Instant::now();
    let mut backoff_ms: u64 = 100;
    let mut request = Some(request);
    for attempt in 1..=MAX_SEND_ATTEMPTS {
        // A non-cloneable body gets a single attempt: the best we can do.
        let (this, last) = match request.as_ref().and_then(reqwest::RequestBuilder::try_clone) {
            Some(clone) => (clone, attempt == MAX_SEND_ATTEMPTS),
            None => match request.take() {
                Some(only) => (only, true),
                // Taken only for a final attempt, which always returns.
                None => return Err(Error::Internal(format!("{label}: request already sent"))),
            },
        };
        let e = match timed_attempt(this, redirects).await {
            Ok(resp) => {
                health.record_success(started.elapsed());
                return Ok(resp);
            }
            Err(Failed::Body(e)) => {
                health.record_failure();
                return Err(Error::Protocol(format!(
                    "{label}: failed to read the response body: {}",
                    redact_url(e)
                )));
            }
            Err(Failed::Send(e)) => e,
        };
        // A refused destination is refused again: one attempt, no health mark.
        if let Some(refused) = crate::security::http_diagnostics::ssrf_refusal(&e) {
            return Err(refused);
        }
        let transient = e.is_connect() || (retry_timeouts && e.is_timeout());
        let e = redact_url(e);
        if transient && !last {
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
    // The final attempt always returns above; the loop cannot fall through.
    unreachable!("send_with_retry exhausted attempts without returning")
}

/// How one attempt failed: before an answer arrived, or reading its body.
enum Failed {
    Send(reqwest::Error),
    Body(reqwest::Error),
}

/// One attempt, timed from the send through the body read, so a slow or
/// stalled body counts and the backoff between attempts does not. The body
/// is read here (every caller reads it whole) and handed back in a rebuilt
/// response, which callers read as they did the original.
async fn timed_attempt(
    request: reqwest::RequestBuilder,
    redirects: &AtomicU64,
) -> std::result::Result<reqwest::Response, Failed> {
    let (client, built) = request.build_split();
    let request = built.map_err(Failed::Send)?;
    let before = redirects.load(Ordering::SeqCst);
    let timer = SendTimer::start();
    let sent = match client.execute(request).await {
        Ok(sent) => sent,
        Err(e) => {
            let evidence = if redirects.load(Ordering::SeqCst) == before {
                RedirectEvidence::NoRedirectFollowed
            } else {
                RedirectEvidence::MayHaveRedirected
            };
            end_send(timer, &e, evidence);
            return Err(Failed::Send(e));
        }
    };
    let (status, version, headers) = (sent.status(), sent.version(), sent.headers().clone());
    match sent.bytes().await {
        Ok(body) => {
            timer.finish(End::Answered);
            let mut rebuilt = axum::http::Response::new(body);
            *rebuilt.status_mut() = status;
            *rebuilt.version_mut() = version;
            *rebuilt.headers_mut() = headers;
            Ok(reqwest::Response::from(rebuilt))
        }
        Err(e) => {
            timer.finish(if e.is_timeout() { End::TimedOut } else { End::Failed });
            Err(Failed::Body(e))
        }
    }
}

/// How a send that failed before any answer ended. An SSRF refusal with no
/// redirect response across the attempt refused the first hop, which was
/// never sent to: nothing is noted. After a redirect response a server
/// answered first, so the send failed (a concurrent call's redirect can only
/// add such a sample: see [`CapabilityClient`]). A timeout is reqwest's own
/// flag, read before the error is wrapped as `Transport`.
fn end_send(timer: SendTimer, e: &reqwest::Error, evidence: RedirectEvidence) {
    if crate::security::http_diagnostics::ssrf_refusal(e).is_some()
        && evidence == RedirectEvidence::NoRedirectFollowed
    {
        timer.discard();
    } else if e.is_timeout() {
        timer.finish(End::TimedOut);
    } else {
        timer.finish(End::Failed);
    }
}
