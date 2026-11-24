// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The per-host verification limit (design §7.2): at most `per_minute`
//! challenge POSTs to one callback host in any 60 s, across principals.
//! The host map is bounded: idle hosts are shed, and only a host not
//! already tracked is refused when the map is full.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// The events verification window.
pub(crate) const WINDOW: Duration = Duration::from_secs(60);

/// A sliding window per key.
pub(crate) struct HostLimiter {
    limit: usize,
    window: Duration,
    max_hosts: usize,
    hosts: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl HostLimiter {
    /// At most `limit` admissions per key in any `window`.
    pub(crate) fn new(limit: u32, window: Duration, max_hosts: usize) -> Self {
        Self {
            limit: usize::try_from(limit).unwrap_or(usize::MAX),
            window,
            max_hosts,
            hosts: Mutex::new(HashMap::new()),
        }
    }

    /// Take one slot for `host` at `now`; `false` when the host is at its
    /// limit, or is new while the map is full of hosts active in the window.
    /// Expired entries are dropped wherever they sit, not only from the
    /// front: callers read `now` before this lock, so entries can arrive out
    /// of order, and `would_admit` counts the same live entries.
    pub(crate) fn admit(&self, host: &str, now: Instant) -> bool {
        let live = |t: &Instant| now.duration_since(*t) < self.window;
        let mut hosts = self.hosts.lock();
        if !hosts.contains_key(host) && hosts.len() >= self.max_hosts {
            hosts.retain(|_, sent| {
                sent.retain(live);
                !sent.is_empty()
            });
            if hosts.len() >= self.max_hosts {
                return false;
            }
        }
        let sent = hosts.entry(host.to_owned()).or_default();
        sent.retain(live);
        if sent.len() >= self.limit {
            return false;
        }
        sent.push_back(now);
        true
    }

    /// Whether `admit` would let `host` in at `now`, recording nothing: for
    /// limits that count only failures, checked before the work is done.
    #[cfg(feature = "webui")] // only the UI's CLI login limits use it
    pub(crate) fn would_admit(&self, host: &str, now: Instant) -> bool {
        let live = |t: &Instant| now.duration_since(*t) < self.window;
        let hosts = self.hosts.lock();
        match hosts.get(host) {
            Some(sent) => sent.iter().filter(|t| live(t)).count() < self.limit,
            // A new key: `admit` takes it if the map has room or would shed
            // an idle key to make some.
            None => {
                self.limit > 0
                    && (hosts.len() < self.max_hosts
                        || hosts.values().any(|sent| !sent.iter().any(live)))
            }
        }
    }

    /// Keys in the map now, live or not yet shed.
    #[cfg(all(test, feature = "webui"))]
    pub(crate) fn tracked(&self) -> usize {
        self.hosts.lock().len()
    }
}

#[cfg(tp5)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_per_host_per_minute_and_recovers() {
        let limiter = HostLimiter::new(2, WINDOW, 10);
        let t0 = Instant::now();
        assert!(limiter.admit("a", t0));
        assert!(limiter.admit("a", t0));
        assert!(!limiter.admit("a", t0), "third in the minute");
        assert!(limiter.admit("b", t0), "per host");
        assert!(limiter.admit("a", t0 + WINDOW), "window slid");
    }

    #[test]
    fn a_full_map_refuses_only_new_hosts_and_sheds_idle_ones() {
        let limiter = HostLimiter::new(5, WINDOW, 2);
        let t0 = Instant::now();
        assert!(limiter.admit("a", t0));
        assert!(limiter.admit("b", t0));
        assert!(!limiter.admit("c", t0), "map full of active hosts");
        assert!(limiter.admit("a", t0), "a tracked host keeps its quota");
        assert!(limiter.admit("c", t0 + WINDOW), "idle hosts shed");
    }
}
