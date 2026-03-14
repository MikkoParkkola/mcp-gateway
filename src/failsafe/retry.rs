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
            .with_max_times(self.max_attempts as usize)
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
