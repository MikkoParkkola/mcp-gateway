//! Rate limiting implementation

use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};

use governor::{Quota, RateLimiter as GovernorLimiter};
use parking_lot::Mutex;

use crate::config::RateLimitConfig;

/// Rate limiter for request throttling
pub struct RateLimiter {
    /// Whether rate limiting is enabled
    enabled: AtomicBool,
    /// Internal rate limiter (lazy initialized)
    inner: Mutex<
        Option<
            GovernorLimiter<
                governor::state::NotKeyed,
                governor::state::InMemoryState,
                governor::clock::DefaultClock,
            >,
        >,
    >,
    /// Quota configuration
    rps: u32,
    burst: u32,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            enabled: AtomicBool::new(config.enabled),
            inner: Mutex::new(None),
            rps: config.requests_per_second,
            burst: config.burst_size,
        }
    }

    /// Try to acquire a permit
    pub fn try_acquire(&self) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            return true;
        }

        let mut inner = self.inner.lock();
        let limiter = inner.get_or_insert_with(|| {
            let quota = Quota::per_second(NonZeroU32::new(self.rps).unwrap_or(NonZeroU32::MIN))
                .allow_burst(NonZeroU32::new(self.burst).unwrap_or(NonZeroU32::MIN));
            GovernorLimiter::direct(quota)
        });

        limiter.check().is_ok()
    }

    /// Enable or disable rate limiting
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }
}
