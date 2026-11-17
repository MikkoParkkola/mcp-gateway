// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-host pacing of capability providers.
//!
//! A provider's `rate_limit` is the policy of its host: every provider that
//! calls a paced host is paced by the same bucket, whichever capability
//! declared the interval. The buckets live in one process-wide map, outside
//! every registry snapshot and executor, so two executors, a retained
//! definition and a call racing a reload all meet the same bucket.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use governor::Quota;
use governor::clock::MonotonicClock;

use crate::capability::CapabilityDefinition;
use crate::failsafe::RateLimiter;

/// The host a request goes to, as pacing counts it: the lowercased host and
/// the effective port, so `HTTPS://Example.ORG/` and `https://example.org:443/`
/// share one bucket.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct HostKey {
    pub(crate) host: String,
    pub(crate) port: u16,
}

/// The [`HostKey`] of `url`, or `None` when it has no host or no known port.
pub(crate) fn host_key(url: &str) -> Option<HostKey> {
    let url = url::Url::parse(url).ok()?;
    Some(HostKey {
        // `Url` already lowercases a domain; an IP literal has no case.
        host: url.host_str()?.to_owned(),
        port: url.port_or_known_default()?,
    })
}

/// One host's bucket and the interval it was built for.
pub(crate) struct Pacer {
    pub(crate) interval_ms: u64,
    pub(crate) limiter: Arc<RateLimiter<MonotonicClock>>,
    /// Whether this bucket ever admitted a request. Only a used bucket's
    /// replacement starts spent: one replaced while a catalogue is still
    /// being registered file by file has admitted nothing to carry over.
    pub(crate) used: AtomicBool,
}

/// Every paced host in the process. Entries live until restart (design v5,
/// n1 N-G1): a retained definition calling a host a reload dropped stays
/// paced.
pub(crate) fn pacers() -> &'static Mutex<HashMap<HostKey, Pacer>> {
    static PACERS: OnceLock<Mutex<HashMap<HostKey, Pacer>>> = OnceLock::new();
    PACERS.get_or_init(Mutex::default)
}

/// A bucket admitting one request per `interval_ms`.
fn limiter(interval_ms: u64) -> Arc<RateLimiter<MonotonicClock>> {
    let quota = Quota::with_period(Duration::from_millis(interval_ms))
        .expect("interval_ms is at least 1 (checked at load)")
        .allow_burst(NonZeroU32::MIN);
    Arc::new(RateLimiter::always_on(quota, MonotonicClock))
}

/// The strictest interval each host in `capabilities` declares: the policy
/// of a host is the longest interval any provider on it asks for.
pub(crate) fn declared_intervals<'a>(
    capabilities: impl IntoIterator<Item = &'a CapabilityDefinition>,
) -> HashMap<HostKey, u64> {
    let mut intervals = HashMap::new();
    for capability in capabilities {
        let providers = capability
            .providers
            .named
            .values()
            .chain(&capability.providers.fallback);
        for provider in providers {
            let Some(rate) = provider.rate_limit else {
                continue;
            };
            let Some(key) = host_key(&provider.config.endpoint) else {
                continue;
            };
            let slot = intervals.entry(key).or_insert(rate.interval_ms);
            *slot = (*slot).max(rate.interval_ms);
        }
    }
    intervals
}

/// Seed the map with `intervals`. A host whose interval is unchanged keeps
/// its bucket; a changed one gets a new bucket, whose first permit is taken
/// before it is inserted when the old bucket was used, so no request is
/// admitted inside the new interval across the switch. Hosts absent from
/// `intervals` keep their entries.
pub(crate) fn seed(intervals: &HashMap<HostKey, u64>) {
    let mut map = pacers().lock().unwrap_or_else(PoisonError::into_inner);
    for (key, &interval_ms) in intervals {
        if map
            .get(key)
            .is_some_and(|pacer| pacer.interval_ms == interval_ms)
        {
            continue;
        }
        let limiter = limiter(interval_ms);
        let was_used = map
            .get(key)
            .is_some_and(|old| old.used.load(std::sync::atomic::Ordering::SeqCst));
        if was_used {
            // Pre-consumed: the switch never opens a free permit.
            let _ = limiter.try_acquire();
        }
        map.insert(
            key.clone(),
            Pacer {
                interval_ms,
                limiter,
                used: AtomicBool::new(was_used),
            },
        );
    }
}
