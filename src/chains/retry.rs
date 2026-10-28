// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Configurable retry with exponential backoff for chain steps.
//!
//! This module provides [`ChainRetryPolicy`] and the async [`retry_step`] helper
//! which retries a fallible future according to that policy.
//!
//! # Example
//!
//! ```rust
//! use mcp_gateway::chains::ChainRetryPolicy;
//! use std::time::Duration;
//!
//! let policy = ChainRetryPolicy::new(3, Duration::from_millis(100));
//! ```

use std::future::Future;
use std::time::Duration;

use tokio::time::sleep;
use tracing::debug;

use crate::jitter::full_jitter;
use crate::{Error, Result};

// ============================================================================
// ChainRetryPolicy
// ============================================================================

/// Retry policy for a single chain step.
///
/// Uses full-jitter exponential backoff to avoid thundering-herd on
/// concurrent chains hitting the same backend.
///
/// # Example
///
/// ```rust
/// use mcp_gateway::chains::ChainRetryPolicy;
/// use std::time::Duration;
///
/// let policy = ChainRetryPolicy::new(3, Duration::from_millis(50))
///     .with_max_backoff(Duration::from_secs(30))
///     .with_multiplier(2.0);
/// ```
#[derive(Debug, Clone)]
pub struct ChainRetryPolicy {
    /// Maximum number of attempts (including the first).
    pub max_attempts: u32,
    /// Initial backoff duration before first retry.
    pub initial_backoff: Duration,
    /// Maximum backoff cap.
    pub max_backoff: Duration,
    /// Exponential multiplier applied per retry.
    pub multiplier: f64,
}

impl ChainRetryPolicy {
    /// Create a policy with the given attempt count and initial backoff.
    #[must_use]
    pub fn new(max_attempts: u32, initial_backoff: Duration) -> Self {
        Self {
            max_attempts,
            initial_backoff,
            max_backoff: Duration::from_secs(60),
            multiplier: 2.0,
        }
    }

    /// Override the maximum backoff cap.
    #[must_use]
    pub fn with_max_backoff(mut self, max_backoff: Duration) -> Self {
        self.max_backoff = max_backoff;
        self
    }

    /// Override the exponential multiplier (default: 2.0).
    #[must_use]
    pub fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier;
        self
    }

    /// Compute the backoff for a given attempt index (0-based, first retry = 0).
    ///
    /// Uses exponential growth capped at `max_backoff`.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    pub fn backoff_for(&self, attempt: u32) -> Duration {
        let exp = self.multiplier.powi(attempt as i32);
        let nanos = (self.initial_backoff.as_nanos() as f64 * exp) as u128;
        let uncapped = Duration::from_nanos(nanos as u64);
        uncapped.min(self.max_backoff)
    }
}

impl Default for ChainRetryPolicy {
    fn default() -> Self {
        Self::new(3, Duration::from_millis(100))
    }
}

// ============================================================================
// retry_step
// ============================================================================

/// Execute `f` with retry according to `policy`, tracking the attempt count.
///
/// Returns `(output, attempts_taken)` on success.
///
/// # Errors
///
/// Returns the last error and the attempts made if all attempts are
/// exhausted or the error is not one a re-send is safe for.
pub async fn retry_step<F, Fut, T>(
    policy: &ChainRetryPolicy,
    step_name: &str,
    mut f: F,
) -> std::result::Result<(T, u32), (Error, u32)>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        match f().await {
            Ok(value) => return Ok((value, attempt)),
            Err(e) if attempt >= policy.max_attempts || !is_retryable(&e) => {
                return Err((e, attempt));
            }
            Err(e) => {
                let bound = policy.backoff_for(attempt - 1);
                // Full jitter, which this module has always documented and did
                // not do: it slept the exact exponential, so every caller
                // retrying the same recovering service came back at the same
                // instant. Spreading each sleep uniformly over [0, bound] is
                // what breaks that synchronisation; `backoff_for` remains the
                // deterministic ceiling, which is what its own tests pin.
                let delay = full_jitter(bound);
                debug!(
                    step = step_name,
                    attempt,
                    delay_ms = delay.as_millis(),
                    bound_ms = bound.as_millis(),
                    error = %e,
                    "Step failed, retrying"
                );
                sleep(delay).await;
            }
        }
    }
}

/// Whether a failed step is re-sent.
///
/// Only an error raised before the request was sent is, so a re-send cannot
/// repeat an effect: `TransportConnect` (the connection was never
/// made) and `BackendUnavailable` (refused before the send: a start, a closed
/// concurrency limit, a cold tools/list timeout; MIK-7979). Both are on
/// [`Error::is_pre_dispatch`], which is checked as well, so the list can
/// never re-send what that allowlist does not vouch for.
///
/// Everything that can follow a send is final: a lost round (`Transport`,
/// `BackendTimeout`), an HTTP error, an I/O error, and a backend's error
/// answer at any status. `JsonRpcRetryable` is the peer's error under 408,
/// 429 or a 5xx, and no status proves the peer did not act (the gateway itself
/// answers 503 for a call that ran and whose audit write failed). Pre-send
/// errors a chain never retried (a missing tool, an authorization wait, an
/// open breaker, a rate limit) stay unretried.
fn is_retryable(error: &Error) -> bool {
    matches!(
        error,
        Error::TransportConnect(_) | Error::BackendUnavailable(_)
    ) && error.is_pre_dispatch()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    /// MIK-7979: start failures and a cold tools/list timeout now surface as
    /// `BackendUnavailable` (pre-send). They were `Transport`/`BackendTimeout`
    /// and retried; the chain must keep retrying them.
    #[test]
    fn a_pre_send_backend_unavailable_is_retried() {
        assert!(is_retryable(&Error::BackendUnavailable("svc".to_string())));
    }

    #[test]
    fn a_permanent_transport_failure_is_not_retried() {
        // Both consumers must agree on the new variant, or a caller's retry
        // behaviour depends on which helper it happened to use.
        assert!(!is_retryable(&Error::TransportPermanent(
            "bad command".to_string()
        )));
        // A plain `Transport` failure may follow a send, so it is final too
        // a connection never made is retried.
        assert!(!is_retryable(&Error::Transport(
            "connection reset".to_string()
        )));
        assert!(is_retryable(&Error::TransportConnect(
            "connection refused".to_string()
        )));
    }

    #[test]
    fn backoff_grows_exponentially() {
        // GIVEN a policy with 100ms initial, 2x multiplier
        let policy = ChainRetryPolicy::new(5, Duration::from_millis(100))
            .with_multiplier(2.0)
            .with_max_backoff(Duration::from_secs(10));
        // WHEN computing backoffs for attempts 0..3
        let b0 = policy.backoff_for(0);
        let b1 = policy.backoff_for(1);
        let b2 = policy.backoff_for(2);
        // THEN each doubles the previous
        assert_eq!(b0, Duration::from_millis(100));
        assert_eq!(b1, Duration::from_millis(200));
        assert_eq!(b2, Duration::from_millis(400));
    }

    #[test]
    fn backoff_caps_at_max() {
        // GIVEN a small max backoff
        let policy = ChainRetryPolicy::new(10, Duration::from_millis(100))
            .with_max_backoff(Duration::from_millis(250));
        // WHEN computing a high attempt index
        let b = policy.backoff_for(10);
        // THEN it is capped
        assert_eq!(b, Duration::from_millis(250));
    }

    /// The gap `retry_step` actually sleeps before its second attempt.
    ///
    /// Measured on a paused clock, so this is the real slept duration rather
    /// than a re-derivation of the policy.
    async fn observed_first_gap(policy: &ChainRetryPolicy) -> Duration {
        let start = tokio::time::Instant::now();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);

        let _ = retry_step::<_, _, ()>(policy, "gap", move || {
            recorder.lock().unwrap().push(start.elapsed());
            std::future::ready(Err(Error::TransportConnect("not ready".to_string())))
        })
        .await;

        let stamps = seen.lock().unwrap();
        stamps[1]
            .checked_sub(stamps[0])
            .expect("the second attempt cannot precede the first")
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_sleeps_are_jittered_not_lockstep() {
        // The doc on this module promises "full-jitter exponential backoff", and
        // the code slept the exact exponential. Concurrent callers retrying the
        // same recovering service therefore hit it in lockstep -- a thundering
        // herd, which is the one thing the jitter was named for.
        //
        // Twenty independent runs. Under full jitter the first gap is uniform in
        // [0, bound], so twenty identical values is not a plausible outcome;
        // under the old code it is the only outcome.
        let policy = ChainRetryPolicy::new(2, Duration::from_millis(100))
            .with_multiplier(2.0)
            .with_max_backoff(Duration::from_secs(10));
        let bound = policy.backoff_for(0);

        let mut gaps = Vec::new();
        for _ in 0..20 {
            gaps.push(observed_first_gap(&policy).await);
        }

        let distinct: std::collections::HashSet<_> = gaps.iter().collect();
        assert!(
            distinct.len() > 1,
            "every retry slept exactly {bound:?} -- no jitter, so concurrent callers stay synchronised"
        );
        assert!(
            gaps.iter().all(|g| *g <= bound),
            "jitter must stay within the computed bound, got {gaps:?} against {bound:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_submillisecond_backoff_is_not_rounded_away() {
        // Raised in review. Millisecond granularity would floor a 100us bound to
        // zero every time, turning a deliberate small backoff into a busy retry.
        let policy = ChainRetryPolicy::new(2, Duration::from_micros(100))
            .with_multiplier(2.0)
            .with_max_backoff(Duration::from_secs(1));

        let mut gaps = Vec::new();
        for _ in 0..20 {
            gaps.push(observed_first_gap(&policy).await);
        }

        assert!(
            gaps.iter().any(|g| !g.is_zero()),
            "every sub-millisecond backoff rounded to zero: {gaps:?}"
        );
    }

    #[tokio::test]
    async fn retry_step_succeeds_on_first_attempt() {
        // GIVEN a function that always succeeds
        let policy = ChainRetryPolicy::new(3, Duration::from_millis(1));
        // WHEN retried
        let (val, attempts) = retry_step(&policy, "step", || async { Ok::<_, Error>(42) })
            .await
            .unwrap();
        // THEN only one attempt was made
        assert_eq!(val, 42);
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn retry_step_retries_transient_errors() {
        // GIVEN a function that fails twice then succeeds
        let call_count = Arc::new(AtomicU32::new(0));
        let cc = call_count.clone();
        let policy = ChainRetryPolicy::new(5, Duration::from_millis(1));

        let (val, attempts) = retry_step(&policy, "flaky", || {
            let count = cc.fetch_add(1, Ordering::SeqCst);
            async move {
                if count < 2 {
                    Err(Error::TransportConnect("transient".into()))
                } else {
                    Ok(99u32)
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(val, 99);
        assert_eq!(attempts, 3);
    }

    #[tokio::test]
    async fn retry_step_exhausts_all_attempts() {
        // GIVEN a function that always fails with a transient error
        let policy = ChainRetryPolicy::new(3, Duration::from_millis(1));
        let call_count = Arc::new(AtomicU32::new(0));
        let cc = call_count.clone();

        let result = retry_step::<_, _, ()>(&policy, "failing", || {
            cc.fetch_add(1, Ordering::SeqCst);
            async { Err(Error::TransportConnect("always fails".into())) }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_step_does_not_retry_permanent_errors() {
        // GIVEN a function that fails with a non-retryable error
        let policy = ChainRetryPolicy::new(5, Duration::from_millis(1));
        let call_count = Arc::new(AtomicU32::new(0));
        let cc = call_count.clone();

        let result = retry_step::<_, _, ()>(&policy, "config_err", || {
            cc.fetch_add(1, Ordering::SeqCst);
            async { Err(Error::Config("bad config".into())) }
        })
        .await;

        assert!(result.is_err());
        // Should have stopped after the first attempt
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    /// A typed HTTP status error, as reqwest raises it.
    fn typed_status(status: u16) -> Error {
        let response = axum::http::Response::builder()
            .status(status)
            .body(String::new())
            .expect("fixture response builds");
        Error::Http(
            reqwest::Response::from(response)
                .error_for_status()
                .expect_err("a fixture status is non-2xx"),
        )
    }

    /// No HTTP status is re-sent: a 401 or 403 repeats with the same
    /// credential (A11-g), and a 429 or 5xx can follow a send.
    #[test]
    fn no_typed_http_status_is_retried() {
        for status in [401, 403, 408, 429, 500, 503] {
            assert!(!is_retryable(&typed_status(status)), "{status}");
        }
    }

    /// Only an error raised before the send is re-sent.
    #[test]
    fn is_retryable_classifies_correctly() {
        assert!(is_retryable(&Error::TransportConnect("x".into())));
        assert!(is_retryable(&Error::BackendUnavailable("x".into())));
        assert!(!is_retryable(&Error::Transport("x".into())));
        assert!(!is_retryable(&Error::BackendTimeout("x".into())));
        assert!(!is_retryable(&Error::Io(std::io::Error::other("x"))));
        for status in [408, 429, 500, 502, 503, 504] {
            let answer = Error::JsonRpcRetryable {
                code: -32000,
                message: "x".into(),
                status,
                data: None,
            };
            assert!(!is_retryable(&answer), "JsonRpcRetryable {status}");
        }
        assert!(!is_retryable(&Error::Config("x".into())));
        assert!(!is_retryable(&Error::Protocol("x".into())));
        assert!(!is_retryable(&Error::BackendNotFound("x".into())));
    }
}
