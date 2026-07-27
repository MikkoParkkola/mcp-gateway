// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Retry logic with exponential backoff

use std::future::Future;
use std::time::Duration;

use backon::{ExponentialBuilder, Retryable};
use tracing::debug;

use crate::Error;
use crate::config::RetryConfig;

/// Retry policy configuration
#[derive(Clone)]
pub struct RetryPolicy {
    /// Whether retries are enabled
    pub enabled: bool,
    /// Maximum attempts
    pub max_attempts: u32,
    /// Initial backoff
    pub initial_backoff: Duration,
    /// Maximum backoff
    pub max_backoff: Duration,
    /// Backoff multiplier
    pub multiplier: f64,
}

impl RetryPolicy {
    /// Create from config
    #[must_use]
    pub fn new(config: &RetryConfig) -> Self {
        Self {
            enabled: config.enabled,
            max_attempts: config.max_attempts,
            initial_backoff: config.initial_backoff,
            max_backoff: config.max_backoff,
            multiplier: config.multiplier,
        }
    }

    /// Build an `ExponentialBuilder` from this policy's parameters.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    fn backoff_builder(&self) -> ExponentialBuilder {
        ExponentialBuilder::new()
            .with_min_delay(self.initial_backoff)
            .with_max_delay(self.max_backoff)
            .with_factor(self.multiplier as f32)
            // backon counts RETRIES, not attempts: `with_max_times(n)` runs one
            // initial call plus n retries. Passing `max_attempts` straight
            // through therefore gave `max_attempts + 1` calls, so an operator
            // configuring `max_attempts: 3` silently got four. Subtract one so
            // the setting means what its name says.
            //
            // `max_attempts: 0` is degenerate; it clamps to a single attempt
            // rather than none, because a request that is never sent at all is
            // never what the operator meant by a retry setting.
            .with_max_times(self.max_attempts.saturating_sub(1) as usize)
    }
}

/// Execute a future with retry logic
///
/// # Errors
///
/// Returns the last error from `f` if all retry attempts are exhausted or
/// the error is not retryable.
pub async fn with_retry<F, Fut, T>(policy: &RetryPolicy, name: &str, mut f: F) -> Result<T, Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, Error>>,
{
    if !policy.enabled {
        return f().await;
    }

    let builder = policy.backoff_builder();
    let op_name = name.to_string();

    (move || f())
        .retry(builder)
        .when(is_retryable)
        .notify(|e: &Error, dur| {
            debug!(
                operation = op_name,
                delay_ms = dur.as_millis(),
                error = %e,
                "Retrying after backoff"
            );
        })
        .await
}

/// Check if an error is retryable
fn is_retryable(error: &Error) -> bool {
    matches!(
        error,
        Error::Transport(_) | Error::BackendTimeout(_) | Error::Http(_) | Error::Io(_)
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn policy(max_attempts: u32) -> RetryPolicy {
        RetryPolicy {
            enabled: true,
            max_attempts,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(1),
            multiplier: 1.0,
        }
    }

    /// Counts how many times the operation is actually invoked for a policy
    /// that always fails with a retryable error.
    async fn invocations_for(max_attempts: u32) -> usize {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let result: Result<(), Error> = with_retry(&policy(max_attempts), "test", move || {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                Err(Error::Transport("always fails".to_string()))
            }
        })
        .await;
        assert!(result.is_err(), "fixture must exhaust every attempt");
        calls.load(Ordering::SeqCst)
    }

    // `max_attempts` must mean attempts, not retries.
    //
    // backon's `with_max_times(n)` runs one initial call plus n retries, so
    // passing the setting through unchanged gave `max_attempts + 1` calls: an
    // operator asking for 3 got 4. That also silently inflated every duration
    // derived from the setting.
    #[tokio::test]
    async fn max_attempts_is_the_total_number_of_calls() {
        assert_eq!(invocations_for(1).await, 1, "1 attempt means no retries");
        assert_eq!(invocations_for(2).await, 2);
        assert_eq!(
            invocations_for(3).await,
            3,
            "the shipped default: three attempts, not four"
        );
    }

    // Degenerate config still sends the request once. Zero attempts would mean
    // a configured backend that never talks to anything, which is never what a
    // retry setting is asking for.
    #[tokio::test]
    async fn zero_attempts_still_sends_the_request_once() {
        assert_eq!(invocations_for(0).await, 1);
    }
}
