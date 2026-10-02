// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The per-host verification limit (design §7.2): at most `per_minute`
//! challenge POSTs to one callback host in any 60 s, across principals.
//! The host map is bounded: idle hosts are shed, and only a host not
//! already tracked is refused when the map is full.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

const WINDOW: Duration = Duration::from_secs(60);

/// A sliding one-minute window per host.
pub(crate) struct HostLimiter {
    per_minute: usize,
    max_hosts: usize,
    hosts: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl HostLimiter {
    pub(crate) fn new(per_minute: u32, max_hosts: usize) -> Self {
        Self {
            per_minute: usize::try_from(per_minute).unwrap_or(usize::MAX),
            max_hosts,
            hosts: Mutex::new(HashMap::new()),
        }
    }

    /// Take one slot for `host` at `now`; `false` when the host is at its
    /// limit, or is new while the map is full of hosts active this minute.
    pub(crate) fn admit(&self, host: &str, now: Instant) -> bool {
        let mut hosts = self.hosts.lock();
        if !hosts.contains_key(host) && hosts.len() >= self.max_hosts {
            hosts.retain(|_, sent| {
                while sent
                    .front()
                    .is_some_and(|t| now.duration_since(*t) >= WINDOW)
                {
                    sent.pop_front();
                }
                !sent.is_empty()
            });
            if hosts.len() >= self.max_hosts {
                return false;
            }
        }
        let sent = hosts.entry(host.to_owned()).or_default();
        while sent
            .front()
            .is_some_and(|t| now.duration_since(*t) >= WINDOW)
        {
            sent.pop_front();
        }
        if sent.len() >= self.per_minute {
            return false;
        }
        sent.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_per_host_per_minute_and_recovers() {
        let limiter = HostLimiter::new(2, 10);
        let t0 = Instant::now();
        assert!(limiter.admit("a", t0));
        assert!(limiter.admit("a", t0));
        assert!(!limiter.admit("a", t0), "third in the minute");
        assert!(limiter.admit("b", t0), "per host");
        assert!(limiter.admit("a", t0 + WINDOW), "window slid");
    }

    #[test]
    fn a_full_map_refuses_only_new_hosts_and_sheds_idle_ones() {
        let limiter = HostLimiter::new(5, 2);
        let t0 = Instant::now();
        assert!(limiter.admit("a", t0));
        assert!(limiter.admit("b", t0));
        assert!(!limiter.admit("c", t0), "map full of active hosts");
        assert!(limiter.admit("a", t0), "a tracked host keeps its quota");
        assert!(limiter.admit("c", t0 + WINDOW), "idle hosts shed");
    }
}
