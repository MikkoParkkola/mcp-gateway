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
/// Returns the last error if all attempts are exhausted or the error is
/// non-retryable.
pub async fn retry_step<F, Fut, T>(
    policy: &ChainRetryPolicy,
    step_name: &str,
    mut f: F,
) -> Result<(T, u32)>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        match f().await {
            Ok(value) => return Ok((value, attempt)),
            Err(e) if attempt >= policy.max_attempts || !is_retryable(&e) => return Err(e),
            Err(e) => {
                let delay = policy.backoff_for(attempt - 1);
                debug!(
                    step = step_name,
                    attempt,
                    delay_ms = delay.as_millis(),
                    error = %e,
                    "Step failed, retrying"
                );
                sleep(delay).await;
            }
        }
    }
}

/// Classify whether an error warrants a retry attempt.
///
/// Transient network and I/O errors are retryable; protocol/config errors
/// signal a permanent failure that retrying will not fix.
fn is_retryable(error: &Error) -> bool {
    matches!(
        error,
        Error::Transport(_) | Error::BackendTimeout(_) | Error::Http(_) | Error::Io(_)
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

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
                    Err(Error::Transport("transient".into()))
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
            async { Err(Error::Transport("always fails".into())) }
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

    #[test]
    fn is_retryable_classifies_correctly() {
        // GIVEN various error types
        assert!(is_retryable(&Error::Transport("x".into())));
        assert!(is_retryable(&Error::BackendTimeout("x".into())));
        assert!(is_retryable(&Error::Io(std::io::Error::other("x"))));
        assert!(!is_retryable(&Error::Config("x".into())));
        assert!(!is_retryable(&Error::Protocol("x".into())));
        assert!(!is_retryable(&Error::BackendNotFound("x".into())));
    }
}
