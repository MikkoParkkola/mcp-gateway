//! Failsafe configuration — circuit breaker, retry, rate limit, health check.

use std::time::Duration;

use serde::{Deserialize, Serialize};

// ── Constants ──────────────────────────────────────────────────────────────────

const DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD: u32 = 5;
const DEFAULT_CIRCUIT_BREAKER_SUCCESS_THRESHOLD: u32 = 3;
const DEFAULT_CIRCUIT_BREAKER_RESET_TIMEOUT_SECS: u64 = 30;

const DEFAULT_RETRY_MAX_ATTEMPTS: u32 = 3;
const DEFAULT_RETRY_INITIAL_BACKOFF_MS: u64 = 100;
const DEFAULT_RETRY_MAX_BACKOFF_SECS: u64 = 10;
const DEFAULT_RETRY_MULTIPLIER: f64 = 2.0;

const DEFAULT_RATE_LIMIT_RPS: u32 = 100;
const DEFAULT_RATE_LIMIT_BURST: u32 = 50;

const DEFAULT_HEALTH_CHECK_INTERVAL_SECS: u64 = 30;
const DEFAULT_HEALTH_CHECK_TIMEOUT_SECS: u64 = 5;

// ── Failsafe ───────────────────────────────────────────────────────────────────

/// Failsafe configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct FailsafeConfig {
    /// Circuit breaker configuration.
    pub circuit_breaker: CircuitBreakerConfig,
    /// Retry configuration.
    pub retry: RetryConfig,
    /// Rate limiting configuration.
    pub rate_limit: RateLimitConfig,
    /// Health check configuration.
    pub health_check: HealthCheckConfig,
}

/// Circuit breaker configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CircuitBreakerConfig {
    /// Enable circuit breaker.
    pub enabled: bool,
    /// Failure threshold before opening.
    pub failure_threshold: u32,
    /// Success threshold to close.
    pub success_threshold: u32,
    /// Time to wait before half-open.
    #[serde(with = "crate::config::humantime_serde")]
    pub reset_timeout: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
            success_threshold: DEFAULT_CIRCUIT_BREAKER_SUCCESS_THRESHOLD,
            reset_timeout: Duration::from_secs(DEFAULT_CIRCUIT_BREAKER_RESET_TIMEOUT_SECS),
        }
    }
}

/// Retry configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RetryConfig {
    /// Enable retries.
    pub enabled: bool,
    /// Maximum retry attempts.
    pub max_attempts: u32,
    /// Initial backoff duration.
    #[serde(with = "crate::config::humantime_serde")]
    pub initial_backoff: Duration,
    /// Maximum backoff duration.
    #[serde(with = "crate::config::humantime_serde")]
    pub max_backoff: Duration,
    /// Backoff multiplier.
    pub multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_attempts: DEFAULT_RETRY_MAX_ATTEMPTS,
            initial_backoff: Duration::from_millis(DEFAULT_RETRY_INITIAL_BACKOFF_MS),
            max_backoff: Duration::from_secs(DEFAULT_RETRY_MAX_BACKOFF_SECS),
            multiplier: DEFAULT_RETRY_MULTIPLIER,
        }
    }
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Enable rate limiting.
    pub enabled: bool,
    /// Requests per second per backend.
    pub requests_per_second: u32,
    /// Burst size.
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: DEFAULT_RATE_LIMIT_RPS,
            burst_size: DEFAULT_RATE_LIMIT_BURST,
        }
    }
}

/// Health check configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HealthCheckConfig {
    /// Enable health checks.
    pub enabled: bool,
    /// Health check interval.
    #[serde(with = "crate::config::humantime_serde")]
    pub interval: Duration,
    /// Health check timeout.
    #[serde(with = "crate::config::humantime_serde")]
    pub timeout: Duration,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: Duration::from_secs(DEFAULT_HEALTH_CHECK_INTERVAL_SECS),
            timeout: Duration::from_secs(DEFAULT_HEALTH_CHECK_TIMEOUT_SECS),
        }
    }
}
