// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MCP Events (MIK-7630): webhook-delivered event subscriptions.
//!
//! Off by default. With `enabled: false` the gateway advertises no `events`
//! capability and every `events/*` method answers `-32601`.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::humantime_serde;
use crate::{Error, Result};

/// Per-subscription delivery rate (delayed, never dropped).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EventsRateLimit {
    /// Sustained deliveries per minute.
    pub per_minute: u32,
    /// Burst above the sustained rate.
    pub burst: u32,
}

impl Default for EventsRateLimit {
    fn default() -> Self {
        Self {
            per_minute: 60,
            burst: 10,
        }
    }
}

/// Which built-in sources are on. Webhook events are opt-in per route.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)] // config surface: independent on/off source switches
pub struct EventsSourcesConfig {
    /// Gateway operational events: budgets, backend health, the kill switch.
    /// Off by default.
    pub operational: bool,
    /// Backend change notifications (`backend.<server>.*`).
    pub backend_notifications: bool,
    /// Task settlement (`task.settled`).
    pub task_settled: bool,
    /// Change notifications for read-only REST capabilities
    /// (`watch.<capability>.changed`). Off by default.
    pub rest_watch: bool,
    /// Cron wake-ups (`schedule.tick`). Off by default.
    pub schedule: bool,
}

/// Bounds on `watch.<capability>.changed` pollers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EventsWatchConfig {
    /// Pollers across all principals.
    pub max_pollers: usize,
    /// Pollers one principal holds alone (credentialed capabilities).
    pub max_pollers_per_principal: usize,
}

impl Default for EventsWatchConfig {
    fn default() -> Self {
        Self {
            max_pollers: 100,
            max_pollers_per_principal: 10,
        }
    }
}

/// Bounds on `schedule.tick` timers (one per distinct cron, timezone, label).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EventsScheduleConfig {
    /// Timers across all principals.
    pub max_timers: usize,
    /// Distinct timers one principal may hold.
    pub max_timers_per_principal: usize,
}

impl Default for EventsScheduleConfig {
    fn default() -> Self {
        Self {
            max_timers: 1000,
            max_timers_per_principal: 20,
        }
    }
}

impl Default for EventsSourcesConfig {
    fn default() -> Self {
        Self {
            operational: false,
            backend_notifications: true,
            task_settled: true,
            rest_watch: false,
            schedule: false,
        }
    }
}

/// The `events:` section. Field meanings follow the design, §9.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EventsConfig {
    /// Master switch.
    pub enabled: bool,
    /// Store root; `~` is expanded at startup.
    pub store_dir: String,
    /// TTL granted when the client suggests none.
    #[serde(with = "humantime_serde")]
    pub default_ttl: Duration,
    /// Floor a finite `ttlMs` is clamped up to.
    #[serde(with = "humantime_serde")]
    pub min_ttl: Duration,
    /// Ceiling a finite `ttlMs` is clamped down to.
    #[serde(with = "humantime_serde")]
    pub max_ttl: Duration,
    /// Whether `ttlMs: null` may produce a subscription without expiry.
    pub allow_no_expiry: bool,
    /// Global subscription cap.
    pub max_subscriptions: usize,
    /// Per-principal subscription cap.
    pub max_subscriptions_per_principal: usize,
    /// Bounded source queue depth.
    pub queue_depth: usize,
    /// Concurrent deliveries across subscriptions.
    pub max_in_flight: usize,
    /// Hard cap on pending outbox records.
    pub max_outbox: usize,
    /// Pending outbox records one subscription may hold.
    pub max_outbox_per_subscription: usize,
    /// Inbound delivery ids remembered per webhook route.
    pub seen_max_per_route: usize,
    /// Verification records kept after their last subscription ended.
    pub max_verified_tail: usize,
    /// As `max_verified_tail`, per principal.
    pub max_verified_tail_per_principal: usize,
    /// How long a verification outlives its last subscription.
    #[serde(with = "humantime_serde")]
    pub verified_tail_ttl: Duration,
    /// Per-subscription delivery rate.
    pub rate_limit_per_subscription: EventsRateLimit,
    /// Charged per delivery attempt when cost governance is on.
    pub cost_per_delivery_usd: f64,
    /// How long the previous secret keeps signing after a rotation.
    #[serde(with = "humantime_serde")]
    pub secret_rotation_grace: Duration,
    /// Dead-letter retention.
    #[serde(with = "humantime_serde")]
    pub dead_letter_retention: Duration,
    /// Dead-letter count cap.
    pub dead_letter_max_records: usize,
    /// Dead-letter byte cap.
    pub dead_letter_max_bytes: u64,
    /// Verification POSTs per destination host per minute, across principals.
    pub verification_per_host_per_minute: u32,
    /// CIDRs a callback may reach although private. Empty = public only.
    pub callback_allow_private: Vec<String>,
    /// Built-in sources.
    pub sources: EventsSourcesConfig,
    /// `watch.<capability>.changed` poller bounds.
    pub watch: EventsWatchConfig,
    /// `schedule.tick` timer bounds.
    pub schedule: EventsScheduleConfig,
    /// First retry delay; later ones grow by a factor of 3, with full jitter.
    #[serde(with = "humantime_serde")]
    pub retry_base: Duration,
    /// Delivery attempts before a record is dead-lettered `exhausted`.
    pub retry_max_attempts: u32,
    /// Span from the first attempt within which every retry must fall; at
    /// most 15 minutes.
    #[serde(with = "humantime_serde")]
    pub retry_window: Duration,
    /// Window over which the failure rate that suspends a subscription is taken.
    #[serde(with = "humantime_serde")]
    pub suspend_window: Duration,
    /// Attempts inside `suspend_window` before the 95 % failure rate applies.
    pub suspend_min_attempts: u32,
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            store_dir: "~/.mcp-gateway/events".to_string(),
            default_ttl: Duration::from_secs(3600),
            min_ttl: Duration::from_secs(60),
            max_ttl: Duration::from_secs(24 * 3600),
            allow_no_expiry: false,
            max_subscriptions: 10_000,
            max_subscriptions_per_principal: 100,
            queue_depth: 1024,
            max_in_flight: 32,
            max_outbox: 50_000,
            max_outbox_per_subscription: 1000,
            seen_max_per_route: 100_000,
            max_verified_tail: 10_000,
            max_verified_tail_per_principal: 100,
            verified_tail_ttl: Duration::from_secs(24 * 3600),
            rate_limit_per_subscription: EventsRateLimit::default(),
            cost_per_delivery_usd: 0.0,
            secret_rotation_grace: Duration::from_secs(600),
            dead_letter_retention: Duration::from_secs(7 * 24 * 3600),
            dead_letter_max_records: 10_000,
            dead_letter_max_bytes: 256 * 1024 * 1024,
            verification_per_host_per_minute: 10,
            callback_allow_private: Vec::new(),
            sources: EventsSourcesConfig::default(),
            watch: EventsWatchConfig::default(),
            schedule: EventsScheduleConfig::default(),
            retry_base: Duration::from_secs(10),
            retry_max_attempts: 5,
            retry_window: Duration::from_secs(15 * 60),
            suspend_window: Duration::from_secs(60 * 60),
            suspend_min_attempts: 100,
        }
    }
}

impl EventsConfig {
    /// Nonzero caps, an ordered TTL range and parseable CIDRs.
    ///
    /// # Errors
    /// [`Error::ConfigValidation`] naming the first offending key.
    pub fn validate(&self) -> Result<()> {
        let fail = |msg: &str| Err(Error::ConfigValidation(format!("events.{msg}")));
        if self.store_dir.trim().is_empty() {
            return fail("store_dir must not be empty");
        }
        if self.min_ttl.is_zero() || self.min_ttl > self.max_ttl {
            return fail("min_ttl must be nonzero and not above max_ttl");
        }
        if self.default_ttl < self.min_ttl || self.default_ttl > self.max_ttl {
            return fail("default_ttl must lie between min_ttl and max_ttl");
        }
        let caps = [
            ("max_subscriptions", self.max_subscriptions),
            (
                "max_subscriptions_per_principal",
                self.max_subscriptions_per_principal,
            ),
            ("queue_depth", self.queue_depth),
            ("max_in_flight", self.max_in_flight),
            ("max_outbox", self.max_outbox),
            (
                "max_outbox_per_subscription",
                self.max_outbox_per_subscription,
            ),
            ("max_verified_tail", self.max_verified_tail),
            (
                "max_verified_tail_per_principal",
                self.max_verified_tail_per_principal,
            ),
            ("watch.max_pollers", self.watch.max_pollers),
            (
                "watch.max_pollers_per_principal",
                self.watch.max_pollers_per_principal,
            ),
            ("schedule.max_timers", self.schedule.max_timers),
            (
                "schedule.max_timers_per_principal",
                self.schedule.max_timers_per_principal,
            ),
        ];
        if let Some((name, _)) = caps.iter().find(|(_, v)| *v == 0) {
            return fail(&format!("{name} must be nonzero"));
        }
        let timings = [
            ("retry_base", self.retry_base),
            ("retry_window", self.retry_window),
            ("suspend_window", self.suspend_window),
        ];
        if let Some((name, _)) = timings.iter().find(|(_, d)| d.is_zero()) {
            return fail(&format!("{name} must be nonzero"));
        }
        if self.retry_window > MAX_RETRY_WINDOW {
            return fail("retry_window must not exceed 15 minutes");
        }
        if self.retry_max_attempts == 0 || self.suspend_min_attempts == 0 {
            return fail("retry_max_attempts and suspend_min_attempts must be nonzero");
        }
        if self.rate_limit_per_subscription.per_minute == 0
            || self.verification_per_host_per_minute == 0
        {
            return fail("rate limits must be nonzero");
        }
        if !self.cost_per_delivery_usd.is_finite() || self.cost_per_delivery_usd < 0.0 {
            return fail("cost_per_delivery_usd must be a finite non-negative number");
        }
        for cidr in &self.callback_allow_private {
            if parse_cidr(cidr).is_none() {
                return fail(&format!("callback_allow_private: {cidr:?} is not a CIDR"));
            }
        }
        Ok(())
    }
}

/// RELIABLE.1: every retry falls within this span of the first attempt.
const MAX_RETRY_WINDOW: Duration = Duration::from_secs(15 * 60);

/// `addr/len` with `len` within the family's width.
pub(crate) fn parse_cidr(text: &str) -> Option<(std::net::IpAddr, u8)> {
    let (addr, len) = text.trim().split_once('/')?;
    let addr: std::net::IpAddr = addr.parse().ok()?;
    let len: u8 = len.parse().ok()?;
    let width = if addr.is_ipv4() { 32 } else { 128 };
    (len <= width).then_some((addr, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate_and_are_off() {
        let config = EventsConfig::default();
        assert!(!config.enabled);
        config.validate().expect("defaults validate");
    }

    #[test]
    fn bad_cidr_and_zero_cap_are_refused() {
        let config = EventsConfig {
            callback_allow_private: vec!["127.0.0.1/33".into()],
            ..EventsConfig::default()
        };
        assert!(config.validate().is_err());
        let config = EventsConfig {
            max_outbox: 0,
            ..EventsConfig::default()
        };
        assert!(config.validate().is_err());
        assert_eq!(parse_cidr("10.0.0.0/8").map(|(_, l)| l), Some(8));
    }

    #[test]
    fn delivery_timing_keys_parse_and_refuse_zero() {
        let config: EventsConfig = serde_yaml::from_str(
            "retry_base: 200ms\nretry_max_attempts: 3\nretry_window: 5s\n\
             suspend_window: 2s\nsuspend_min_attempts: 4\n",
        )
        .expect("timing keys parse");
        assert_eq!(config.retry_base, Duration::from_millis(200));
        assert_eq!(config.retry_max_attempts, 3);
        config.validate().expect("valid timings");
        let defaults = EventsConfig::default();
        assert_eq!(defaults.retry_base, Duration::from_secs(10));
        assert_eq!(defaults.suspend_min_attempts, 100);
        for zero in [
            EventsConfig {
                retry_base: Duration::ZERO,
                ..EventsConfig::default()
            },
            EventsConfig {
                retry_max_attempts: 0,
                ..EventsConfig::default()
            },
            EventsConfig {
                suspend_window: Duration::ZERO,
                ..EventsConfig::default()
            },
        ] {
            assert!(zero.validate().is_err());
        }
    }

    /// RELIABLE.1: every retry falls within 15 minutes of the first attempt,
    /// so a longer window is refused at load, naming the field (MIK-7784).
    #[test]
    fn a_retry_window_over_fifteen_minutes_is_refused_by_name() {
        let at = |secs| EventsConfig {
            retry_window: Duration::from_secs(secs),
            ..EventsConfig::default()
        };
        at(15 * 60).validate().expect("15 minutes is the bound");
        let error = at(15 * 60 + 1).validate().expect_err("over the bound");
        assert!(error.to_string().contains("retry_window"), "{error}");
    }
}
