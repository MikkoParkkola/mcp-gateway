//! Retry logic with exponential backoff

use std::future::Future;
use std::time::Duration;

use backoff::ExponentialBackoff;
use backoff::backoff::Backoff;
use tokio::time::sleep;
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

    /// Create an exponential backoff instance
    #[must_use]
    pub fn create_backoff(&self) -> ExponentialBackoff {
        ExponentialBackoff {
            current_interval: self.initial_backoff,
            initial_interval: self.initial_backoff,
            max_interval: self.max_backoff,
            multiplier: self.multiplier,
            max_elapsed_time: None,
            ..Default::default()
        }
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

    let mut backoff = policy.create_backoff();
    let mut attempts = 0u32;

    loop {
        attempts += 1;

        match f().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                // Don't retry certain errors
                if !is_retryable(&e) {
                    return Err(e);
                }

                if attempts >= policy.max_attempts {
                    debug!(
                        operation = name,
                        attempts = attempts,
                        "Max retry attempts reached"
                    );
                    return Err(e);
                }

                if let Some(duration) = backoff.next_backoff() {
                    debug!(
                        operation = name,
                        attempt = attempts,
                        delay_ms = duration.as_millis(),
                        error = %e,
                        "Retrying after backoff"
                    );
                    sleep(duration).await;
                } else {
                    return Err(e);
                }
            }
        }
    }
}

/// Check if an error is retryable
fn is_retryable(error: &Error) -> bool {
    matches!(
        error,
        Error::Transport(_) | Error::BackendTimeout(_) | Error::Http(_) | Error::Io(_)
    )
}
