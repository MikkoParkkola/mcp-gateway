// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A sliding-window observation ledger keyed on the authenticated principal.
//!
//! Two controls in this release need the same thing: *what has this caller
//! done lately*. MIK-7215.CONTROL.2 needs how **many** calls; MIK-7116.TENANT.1
//! needs how many **distinct** tenants. Both were specified against the session
//! and the session is gone, so both are rebound to the principal here, once.
//!
//! # Why the window is explicit
//!
//! A counter with no window is a lifetime quota: it only ever rises, so the
//! first caller to reach the limit is refused forever. A counter keyed on a
//! session under a stateless transport is the opposite failure — the key is new
//! on every request, so the count is always one and the limit is never reached.
//! An explicit window is what makes the count mean *recent* rather than *ever*
//! or *never*.
//!
//! # Why expiry, not disconnect
//!
//! There is no disconnect in a stateless transport, so state reclaimed by a
//! disconnect handler is never reclaimed at all (MIK-7215.CONTROL.4). Entries
//! here leave by ageing out of the window, swept on the access that notices
//! them. Nothing has to fire, so nothing can fail to fire.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// The most principals whose recent activity is remembered at once.
///
/// A backstop against unbounded growth from an attacker minting identities,
/// not a policy: entries normally leave by ageing out. Sized well above any
/// plausible concurrent caller count so eviction is not an ordinary event.
const MAX_TRACKED_PRINCIPALS: usize = 100_000;

/// The most observations retained for one principal.
///
/// Bounds the memory a single busy caller can hold. Once reached the oldest
/// observation is dropped, which can only ever *understate* usage — a budget
/// that undercounts refuses too little, whereas one that overcounts refuses a
/// caller for calls it did not make.
const MAX_OBSERVATIONS_PER_PRINCIPAL: usize = 4_096;

/// What the ledger could establish about one caller.
///
/// An enum rather than a `usize`, for the reason
/// [`crate::security::firewall::anomaly::Observation`] is an enum: every caller
/// compares the count against a limit, and `0` compares below every limit. "I
/// have no key to count against" would otherwise be indistinguishable from "I
/// counted, and this caller has spent nothing" — at every call site, in
/// silence. The requirement names that exact failure: a per-session budget
/// under statelessness is an unlimited budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Usage {
    /// Observations recorded for this principal inside the window.
    Counted {
        /// Every observation, including repeats of the same value.
        total: usize,
        /// Distinct observation values.
        distinct: usize,
    },
    /// No principal to key on, so nothing could be counted.
    Unkeyed,
}

/// Recent observations per principal, bounded in count and in time.
pub struct PrincipalWindow {
    window: Duration,
    entries: DashMap<String, VecDeque<(Instant, String)>>,
}

impl PrincipalWindow {
    /// Create a ledger retaining observations for `window`.
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            entries: DashMap::new(),
        }
    }

    /// Record one observation for `principal` and report its recent activity.
    ///
    /// `principal` is the authenticated caller. `None` — or an empty string,
    /// which is a valid map key and therefore the dangerous near-miss — means
    /// there is no caller to attribute this to, and the answer is
    /// [`Usage::Unkeyed`]. Pooling anonymous callers under one key would be
    /// worse than no budget: whoever calls most exhausts everyone else's.
    pub fn record(&self, principal: Option<&str>, observation: &str) -> Usage {
        self.record_at(principal, observation, Instant::now())
    }

    /// [`Self::record`] against a caller-supplied instant.
    ///
    /// Exists so window behaviour is tested by arithmetic rather than by
    /// sleeping: a test that sleeps proves only that the machine was slow
    /// enough that day.
    pub fn record_at(&self, principal: Option<&str>, observation: &str, now: Instant) -> Usage {
        let Some(key) = Self::key(principal) else {
            return Usage::Unkeyed;
        };

        self.evict_if_full();

        let mut recent = self.entries.entry(key).or_default();
        recent.push_back((now, observation.to_string()));
        if recent.len() > MAX_OBSERVATIONS_PER_PRINCIPAL {
            recent.pop_front();
        }
        Self::retain_live(&mut recent, now, self.window);

        Usage::Counted {
            total: recent.len(),
            distinct: Self::distinct(&recent),
        }
    }

    /// Drop every observation that has aged out, and every principal left with
    /// none.
    ///
    /// Called on the ordinary access path, so reclamation needs no scheduler
    /// and no disconnect. Exposed for the expiry acceptance tests.
    pub fn expire_at(&self, now: Instant) {
        self.entries.retain(|_, recent| {
            Self::retain_live(recent, now, self.window);
            !recent.is_empty()
        });
    }

    /// Principals currently holding at least one live observation.
    #[must_use]
    pub fn tracked_principals(&self) -> usize {
        self.entries.len()
    }

    /// The map key for a principal, or `None` when there is no principal.
    fn key(principal: Option<&str>) -> Option<String> {
        principal
            .filter(|p| !p.is_empty())
            .map(std::string::ToString::to_string)
    }

    /// Drop the leading run of observations older than `window`.
    ///
    /// A `VecDeque` in insertion order, so ageing out is a prefix: the first
    /// entry still inside the window ends the sweep.
    fn retain_live(recent: &mut VecDeque<(Instant, String)>, now: Instant, window: Duration) {
        while let Some((at, _)) = recent.front() {
            if now.saturating_duration_since(*at) > window {
                recent.pop_front();
            } else {
                break;
            }
        }
    }

    /// Distinct observation values in a principal's live history.
    fn distinct(recent: &VecDeque<(Instant, String)>) -> usize {
        recent
            .iter()
            .map(|(_, value)| value.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len()
    }

    /// Evict an arbitrary principal when the ledger is at its ceiling.
    ///
    /// Reached only when ageing out has not kept pace, which needs identities
    /// minted faster than the window retires them.
    fn evict_if_full(&self) {
        if self.entries.len() < MAX_TRACKED_PRINCIPALS {
            return;
        }
        if let Some(victim) = self.entries.iter().next().map(|e| e.key().clone()) {
            self.entries.remove(&victim);
        }
    }
}
