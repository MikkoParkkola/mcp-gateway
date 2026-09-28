// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Tool sequence anomaly detection using transition probability data.
//!
//! Uses the existing `TransitionTracker` to score how "unusual" a tool
//! invocation is given the previous tool called in the same session.
//!
//! # Scoring
//!
//! Each call is scored against the caller's own predecessor, using what the
//! detector has learned from calls the firewall admitted:
//!
//! | Condition | Result |
//! |-----------|--------|
//! | First call for this identity | `WarmingUp` (not a score) |
//! | Predecessor with fewer than `anomaly_min_observations` transitions | `WarmingUp` |
//! | Current tool seen after the predecessor | `1.0 - confidence` |
//! | Current tool never seen after the predecessor | 1.0 |
//!
//! Scores at or above `anomaly_threshold` (default 0.7) are logged; at or
//! above `anomaly_block_threshold` the call is refused, and no firewall rule
//! can downgrade that refusal.
//!
//! # Learning
//!
//! [`AnomalyDetector::begin`] scores without learning; the firewall calls
//! [`AnomalyDetector::commit`] only for an admitted call, so a refused call
//! never teaches the detector. Before #1756 nothing recorded into the tracker
//! the firewall held, and every call scored a neutral 0.5.
//!
//! # Session lifecycle
//!
//! Call `remove_session` (via the `SessionLifecycle` hook) when a session
//! disconnects to prevent unbounded memory growth.

use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

use crate::transition::TransitionTracker;

/// The most callers whose last tool is remembered at once.
///
/// A ceiling rather than a policy: the mechanism that should reclaim these on
/// disconnect is not wired, and a stateless caller has no disconnect to reclaim
/// on. Sized well above any plausible concurrent caller count so eviction is a
/// backstop and not an ordinary event.
const MAX_TRACKED_IDENTITIES: usize = 100_000;

/// Number of per-identity scoring locks.
const STRIPES: usize = 64;

/// Distinct learned transitions kept; a new one past this is counted, not kept.
const MAX_LEARNED_PAIRS: usize = 100_000;

/// Default `firewall.anomaly_min_observations`.
const DEFAULT_MIN_OBSERVATIONS: u64 = 20;

/// Per-session anomaly detector backed by transition probability data.
pub struct AnomalyDetector {
    tracker: Arc<TransitionTracker>,
    threshold: f64,
    /// Per-session last tool, used to compute P(current | last).
    ///
    /// Key: `session_id`, Value: last tool key (`"server:tool"`).
    last_tool: DashMap<String, String>,
    /// Per-identity scoring locks, striped by a hash of the identity.
    stripes: Box<[parking_lot::Mutex<()>]>,
    /// Transitions a predecessor needs before its successors are scored.
    min_observations: u64,
    /// Calls answered `WarmingUp`.
    warming_up: AtomicU64,
    /// New transitions not learned because the pair map was full.
    pairs_dropped: AtomicU64,
}

/// A call scored by [`AnomalyDetector::begin`] and not yet learned.
///
/// Holds the identity's scoring lock; dropping it without
/// [`AnomalyDetector::commit`] learns nothing.
pub(crate) struct Scoring<'a> {
    _lock: parking_lot::MutexGuard<'a, ()>,
    identity: String,
    prev: Option<String>,
    current: String,
}

/// What the detector could establish about one call.
///
/// An enum rather than an `f64` sentinel, and that is the whole design. Every
/// comparison downstream reads `score > threshold`; a sentinel like `-1.0` or
/// `NaN` compares `false` against any threshold, so "I could not look" would be
/// indistinguishable from "I looked and it was fine" at every call site, in
/// silence. A variant forces each caller to say what it does when the control
/// cannot see.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Observation {
    /// A score in `[0.0, 1.0]`; 1.0 means never observed before.
    Scored(f64),
    /// No identity to key on, so no transition could be established.
    ///
    /// Under MCP 2026-07-28 there is no session. A detector keyed on one sees a
    /// first request every time and returns its neutral score forever — it
    /// keeps running and stops protecting, which is the failure this variant
    /// exists to make visible.
    Unobservable,
    /// Too little history to judge: the caller's first call, or a predecessor
    /// with fewer recorded transitions than the configured minimum.
    ///
    /// Not a score. A neutral number here would be compared against the
    /// operator's thresholds like any other, so a threshold at or below it
    /// would flag every call made while the detector was still learning.
    WarmingUp,
}

impl Observation {
    /// The score, or `None` when nothing could be observed.
    #[must_use]
    pub const fn score(self) -> Option<f64> {
        match self {
            Self::Scored(value) => Some(value),
            Self::Unobservable | Self::WarmingUp => None,
        }
    }
}

impl AnomalyDetector {
    /// Score a call against the caller's own recent history, and learn it.
    ///
    /// `identity` is the stable per-caller key. `None` means the caller could
    /// not be identified, and the honest answer is then
    /// [`Observation::Unobservable`] rather than a passing score. Per caller,
    /// never globally: one caller's ordinary sequence must not make another's
    /// unusual one look ordinary. Scores and learns in one step; the firewall
    /// uses [`Self::begin`] and [`Self::commit`] so a refused call is not
    /// learned.
    pub fn observe(&self, identity: Option<&str>, server: &str, tool: &str) -> Observation {
        let (observation, scoring) = self.begin(identity, server, tool);
        if let Some(scoring) = scoring {
            self.commit(scoring);
        }
        observation
    }

    /// Create a new detector.
    ///
    /// `threshold` is the score above which a transition is considered
    /// anomalous (0.0–1.0; default is 0.7).
    pub fn new(tracker: Arc<TransitionTracker>, threshold: f64) -> Self {
        Self {
            tracker,
            threshold,
            min_observations: DEFAULT_MIN_OBSERVATIONS,
            last_tool: DashMap::new(),
            stripes: (0..STRIPES).map(|_| parking_lot::Mutex::new(())).collect(),
            warming_up: AtomicU64::new(0),
            pairs_dropped: AtomicU64::new(0),
        }
    }

    /// Score and learn one call, as [`Self::observe`] does.
    ///
    /// Returns a value in `[0.0, 1.0]` where 1.0 means "never observed". A
    /// call that is still warming up answers 0.5; callers that must tell the
    /// two apart use [`Self::observe`].
    pub fn score_transition(&self, identity: &str, server: &str, tool: &str) -> f64 {
        match self.observe(Some(identity), server, tool) {
            Observation::Scored(score) => score,
            Observation::Unobservable | Observation::WarmingUp => 0.5,
        }
    }

    /// Score a call without learning it, holding the identity's scoring lock.
    ///
    /// The lock is held until the returned [`Scoring`] is committed or
    /// dropped, so calls from one identity are judged one at a time and never
    /// against a predecessor another call is about to replace. It is a
    /// separate stripe lock, not a map entry guard: the capacity path in
    /// [`Self::commit`] reads the whole map, which would deadlock against a
    /// held entry guard on the same shard.
    pub(crate) fn begin(
        &self,
        identity: Option<&str>,
        server: &str,
        tool: &str,
    ) -> (Observation, Option<Scoring<'_>>) {
        let Some(identity) = identity else {
            return (Observation::Unobservable, None);
        };
        let lock = self.stripe(identity).lock();
        let current = format!("{server}:{tool}");
        let prev = self
            .last_tool
            .get(identity)
            .map(|entry| entry.value().clone());
        self.last_tool.insert(identity.to_owned(), current.clone());
        let observation = match prev.as_deref() {
            None => Observation::WarmingUp,
            Some(prev) => self.score_after(prev, &current),
        };
        if observation == Observation::WarmingUp {
            self.warming_up.fetch_add(1, Ordering::Relaxed);
        }
        let scoring = Scoring {
            _lock: lock,
            identity: identity.to_owned(),
            prev,
            current,
        };
        (observation, Some(scoring))
    }

    /// Learn a call the firewall admitted, and release its scoring lock.
    pub(crate) fn commit(&self, scoring: Scoring<'_>) {
        let Scoring {
            _lock,
            identity,
            prev,
            current,
        } = scoring;
        // Bounded: every distinct identity leaves a predecessor behind and a
        // stateless caller never disconnects, so without a ceiling this map
        // is a memory-exhaustion vector. Evicting an arbitrary entry costs
        // that caller its predecessor, nothing more.
        if self.last_tool.len() >= MAX_TRACKED_IDENTITIES && !self.last_tool.contains_key(&identity)
        {
            // The victim is chosen in its OWN statement so the iterator's
            // shard lock is dropped before `remove` asks for it as a writer.
            let victim = self.last_tool.iter().next().map(|e| e.key().clone());
            if let Some(victim) = victim {
                self.last_tool.remove(&victim);
            }
        }
        self.last_tool.insert(identity, current.clone());
        if let Some(prev) = prev
            && !self.tracker.record_pair(&prev, &current, MAX_LEARNED_PAIRS)
            && self.pairs_dropped.fetch_add(1, Ordering::Relaxed) == 0
        {
            // Once, not per call: a full map drops every new transition.
            tracing::warn!(
                max_pairs = MAX_LEARNED_PAIRS,
                "OWASP ASI10: anomaly detector's learned-transition map is full; new \
                 transitions are no longer learned"
            );
        }
    }

    /// The score of `current` after `prev`, or `WarmingUp` when `prev` has
    /// fewer recorded transitions than the configured minimum.
    fn score_after(&self, prev: &str, current: &str) -> Observation {
        if self.tracker.successor_total(prev) < self.min_observations {
            return Observation::WarmingUp;
        }
        let predictions = self.tracker.predict_next(prev, 0.0, 0);
        match predictions.iter().find(|p| p.tool == current) {
            Some(p) => Observation::Scored(1.0 - p.confidence),
            // Never seen: the most unusual a transition can be, so never
            // below a rare one (`1 - confidence` approaches 1.0 from below).
            None => Observation::Scored(1.0),
        }
    }

    fn stripe(&self, identity: &str) -> &parking_lot::Mutex<()> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        identity.hash(&mut hasher);
        #[allow(clippy::cast_possible_truncation)] // modulo STRIPES fits usize
        let index = (hasher.finish() % STRIPES as u64) as usize;
        &self.stripes[index]
    }

    /// The configured anomaly threshold.
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Set how many transitions a predecessor needs before its successors are
    /// scored (`firewall.anomaly_min_observations`).
    #[must_use]
    pub fn with_min_observations(mut self, min_observations: u64) -> Self {
        self.min_observations = min_observations;
        self
    }

    /// Calls answered [`Observation::WarmingUp`] since start.
    #[cfg(test)]
    pub(crate) fn warming_up_count(&self) -> u64 {
        self.warming_up.load(Ordering::Relaxed)
    }

    /// Hold `identity`'s scoring lock, so a test can prove a concurrent call
    /// for the same identity waits for it.
    /// The tracker this detector learns into.
    #[cfg(test)]
    pub(crate) fn tracker_for_test(&self) -> &TransitionTracker {
        &self.tracker
    }

    #[cfg(test)]
    pub(crate) fn hold_stripe(&self, identity: &str) -> parking_lot::MutexGuard<'_, ()> {
        self.stripe(identity).lock()
    }

    /// Remove per-session state when a session disconnects.
    ///
    /// Register this via `SessionLifecycle::register` at gateway startup.
    pub fn remove_session(&self, session_id: &str) {
        self.last_tool.remove(session_id);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {

    #[test]
    fn the_identity_map_is_bounded() {
        // Every distinct identity leaves a predecessor behind and nothing
        // reclaims one: the cleanup registry is not wired to anything, and a
        // stateless caller never disconnects because it never connected. Without
        // a ceiling this is a memory-exhaustion vector reachable by anyone who
        // can present distinct credentials.
        let tracker = Arc::new(TransitionTracker::new());
        let detector = AnomalyDetector::new(tracker, 0.7);

        for n in 0..(MAX_TRACKED_IDENTITIES + 500) {
            detector.score_transition(&format!("caller-{n}"), "srv", "tool");
        }

        assert!(
            detector.last_tool.len() <= MAX_TRACKED_IDENTITIES,
            "the identity map must hold its ceiling, got {}",
            detector.last_tool.len()
        );
    }
    use super::*;

    fn empty_tracker() -> Arc<TransitionTracker> {
        Arc::new(TransitionTracker::new())
    }

    // ── Cold-start behaviour ──────────────────────────────────────────────────

    #[test]
    fn cold_start_returns_neutral_score() {
        let detector = AnomalyDetector::new(empty_tracker(), 0.7);
        let score = detector.score_transition("sess1", "srv", "tool_a");
        assert!(
            (score - 0.5).abs() < f64::EPSILON,
            "Expected 0.5 for first call, got {score}"
        );
    }

    #[test]
    fn cold_start_predecessor_returns_neutral() {
        // Predecessor exists but tracker has no data for it.
        let detector = AnomalyDetector::new(empty_tracker(), 0.7);
        // First call — establishes "tool_a" as last tool.
        let _ = detector.score_transition("sess1", "srv", "tool_a");
        // Second call — predecessor "srv:tool_a" has no transitions.
        let score = detector.score_transition("sess1", "srv", "tool_b");
        assert!(
            (score - 0.5).abs() < f64::EPSILON,
            "Expected neutral 0.5 for unknown predecessor, got {score}"
        );
    }

    // ── Known transition ──────────────────────────────────────────────────────

    #[test]
    fn frequent_transition_yields_low_score() {
        let tracker = Arc::new(TransitionTracker::new());
        // Record tool_a → tool_b many times to build high confidence.
        for _ in 0..20 {
            tracker.record_transition("sess-train", "srv:tool_a");
            tracker.record_transition("sess-train", "srv:tool_b");
        }

        let detector = AnomalyDetector::new(Arc::clone(&tracker), 0.7);
        // Prime last_tool = "srv:tool_a"
        detector.score_transition("sess-test", "srv", "tool_a");
        // Score the known successor
        let score = detector.score_transition("sess-test", "srv", "tool_b");
        assert!(
            score < 0.7,
            "Frequent transition should score below threshold, got {score}"
        );
    }

    // ── Never-seen transition ─────────────────────────────────────────────────

    #[test]
    fn never_seen_transition_yields_high_score() {
        let tracker = Arc::new(TransitionTracker::new());
        // Record tool_a → tool_b only.
        for _ in 0..10 {
            tracker.record_transition("sess-train", "srv:tool_a");
            tracker.record_transition("sess-train", "srv:tool_b");
        }

        let detector = AnomalyDetector::new(Arc::clone(&tracker), 0.7).with_min_observations(1);
        // Prime last_tool = "srv:tool_a"
        detector.score_transition("sess-test", "srv", "tool_a");
        // Score a tool that has NEVER followed tool_a.
        let score = detector.score_transition("sess-test", "srv", "totally_unknown");
        assert!(
            (score - 1.0).abs() < f64::EPSILON,
            "Expected 1.0 for never-seen transition, got {score}"
        );
    }

    // ── Session cleanup ───────────────────────────────────────────────────────

    #[test]
    fn remove_session_resets_last_tool() {
        let detector = AnomalyDetector::new(empty_tracker(), 0.7);
        // Establish last_tool for session.
        detector.score_transition("sess1", "srv", "tool_a");
        assert!(detector.last_tool.contains_key("sess1"));

        // Remove session.
        detector.remove_session("sess1");
        assert!(!detector.last_tool.contains_key("sess1"));

        // Next call on same session is cold-start again.
        let score = detector.score_transition("sess1", "srv", "tool_b");
        assert!(
            (score - 0.5).abs() < f64::EPSILON,
            "After removal, next call should be cold-start 0.5, got {score}"
        );
    }

    #[test]
    fn remove_nonexistent_session_is_noop() {
        let detector = AnomalyDetector::new(empty_tracker(), 0.7);
        detector.remove_session("does-not-exist"); // must not panic
    }

    // ── Multi-session isolation ───────────────────────────────────────────────

    #[test]
    fn sessions_are_isolated() {
        let detector = AnomalyDetector::new(empty_tracker(), 0.7);
        detector.score_transition("sess1", "srv", "tool_a");
        detector.score_transition("sess2", "srv", "tool_x");

        // sess1's last tool is tool_a; sess2's is tool_x — different entries.
        assert_eq!(
            detector.last_tool.get("sess1").as_deref().cloned(),
            Some("srv:tool_a".to_string())
        );
        assert_eq!(
            detector.last_tool.get("sess2").as_deref().cloned(),
            Some("srv:tool_x".to_string())
        );
    }

    // ── #1756: learning, warm-up and monotonic scores ─────────────────────────

    /// A tracker where `srv:tool_a` has been followed `n` times by `srv:tool_b`.
    fn trained(n: usize) -> Arc<TransitionTracker> {
        let tracker = Arc::new(TransitionTracker::new());
        for _ in 0..n {
            tracker.record_transition("train", "srv:tool_a");
            tracker.record_transition("train", "srv:tool_b");
        }
        tracker
    }

    #[test]
    fn never_seen_scores_one_and_above_rare() {
        // 99 x a->b and 1 x a->c: c is rare (0.99), d was never seen (1.0).
        // A never-seen transition must never score below a rare one.
        let tracker = Arc::new(TransitionTracker::new());
        for n in 0..99 {
            let caller = format!("t{n}");
            tracker.record_transition(&caller, "srv:tool_a");
            tracker.record_transition(&caller, "srv:tool_b");
        }
        tracker.record_transition("t", "srv:tool_a");
        tracker.record_transition("t", "srv:tool_c");
        let detector = AnomalyDetector::new(tracker, 0.7).with_min_observations(1);

        detector.score_transition("rare", "srv", "tool_a");
        let rare = detector.score_transition("rare", "srv", "tool_c");
        detector.score_transition("never", "srv", "tool_a");
        let never = detector.score_transition("never", "srv", "tool_d");

        assert!(
            (never - 1.0).abs() < f64::EPSILON,
            "never-seen must score 1.0, got {never}"
        );
        assert!(
            rare < never,
            "rare ({rare}) must score below never-seen ({never})"
        );
    }

    #[test]
    fn cold_predecessor_is_warming_up() {
        // A first call has no predecessor, and a predecessor with 5 recorded
        // transitions is below the minimum of 20: neither is a score.
        let detector = AnomalyDetector::new(trained(5), 0.7).with_min_observations(20);
        assert_eq!(
            detector.observe(Some("id"), "srv", "tool_a"),
            Observation::WarmingUp
        );
        assert_eq!(
            detector.observe(Some("id"), "srv", "tool_b"),
            Observation::WarmingUp
        );
        assert_eq!(detector.warming_up_count(), 2);
    }

    #[test]
    fn warmup_counts_total_transitions() {
        // Warm-up counts every recorded transition out of the predecessor, not
        // distinct successors: 20 transitions to ONE successor are enough.
        let warm = AnomalyDetector::new(trained(20), 0.7).with_min_observations(20);
        warm.observe(Some("id"), "srv", "tool_a");
        assert!(
            matches!(
                warm.observe(Some("id"), "srv", "tool_b"),
                Observation::Scored(_)
            ),
            "20 transitions out of tool_a meet a minimum of 20"
        );

        let cold = AnomalyDetector::new(trained(19), 0.7).with_min_observations(20);
        cold.observe(Some("id"), "srv", "tool_a");
        assert_eq!(
            cold.observe(Some("id"), "srv", "tool_b"),
            Observation::WarmingUp
        );
    }

    #[test]
    fn serialized_at_identity_cap_no_deadlock() {
        // The capacity path (len/iter over the identity map) runs while the
        // identity's scoring lock is held. Holding a map entry guard there
        // instead would deadlock the thread against itself.
        let detector = Arc::new(AnomalyDetector::new(empty_tracker(), 0.7));
        for n in 0..MAX_TRACKED_IDENTITIES {
            detector.score_transition(&format!("filler-{n}"), "srv", "tool");
        }
        let worker = Arc::clone(&detector);
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for n in 0..1_000 {
                worker.observe(Some(&format!("new-{n}")), "srv", "tool");
            }
            let _ = done.send(());
        });
        finished
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("1,000 calls at the identity cap must finish, not deadlock");
        assert!(
            detector.warming_up_count() >= 1_000,
            "every new identity's first call is a warm-up, got {}",
            detector.warming_up_count()
        );
        assert!(detector.last_tool.len() <= MAX_TRACKED_IDENTITIES);
    }
}
