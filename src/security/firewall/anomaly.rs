// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Tool sequence anomaly detection using transition probability data.
//!
//! Uses the existing `TransitionTracker` to score how "unusual" a tool
//! invocation is given the previous tool called in the same session.
//!
//! # Scoring
//!
//! The anomaly score is a value in `[0.0, 1.0]`:
//!
//! | Condition | Score | Meaning |
//! |-----------|-------|---------|
//! | First tool in session (no prior context) | 0.5 | Neutral — no data |
//! | Known predecessor, no data for it | 0.5 | Cold start — neutral |
//! | Current tool appears in predictions | `1.0 - confidence` | Lower confidence → higher anomaly |
//! | Current tool never seen after predecessor | 0.95 | Very unusual |
//!
//! Scores above the configured `anomaly_threshold` (default 0.7) are flagged
//! as `Severity::Low` findings, which produce an audit log entry but do not
//! block or warn by default.
//!
//! # Session lifecycle
//!
//! Call `remove_session` (via the `SessionLifecycle` hook) when a session
//! disconnects to prevent unbounded memory growth.

use std::sync::Arc;

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

/// Per-session anomaly detector backed by transition probability data.
pub struct AnomalyDetector {
    tracker: Arc<TransitionTracker>,
    threshold: f64,
    /// Per-session last tool, used to compute P(current | last).
    ///
    /// Key: `session_id`, Value: last tool key (`"server:tool"`).
    last_tool: DashMap<String, String>,
    /// Per-identity scoring locks, striped by a hash of the identity.
    #[allow(dead_code, reason = "red-first stub: the fix commit uses it")]
    stripes: Box<[parking_lot::Mutex<()>]>,
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
    /// Score a call against the caller's own recent history.
    ///
    /// `identity` is the stable per-caller key — the authenticated principal
    /// after the migration, the session before it. `None` means the caller
    /// could not be identified, and the honest answer is then
    /// [`Observation::Unobservable`] rather than a passing score.
    ///
    /// Per caller, never globally: one caller's ordinary sequence must not make
    /// another's unusual one look ordinary.
    pub fn observe(&self, identity: Option<&str>, server: &str, tool: &str) -> Observation {
        let Some(identity) = identity else {
            return Observation::Unobservable;
        };
        Observation::Scored(self.score_transition(identity, server, tool))
    }

    /// Create a new detector.
    ///
    /// `threshold` is the score above which a transition is considered
    /// anomalous (0.0–1.0; default is 0.7).
    pub fn new(tracker: Arc<TransitionTracker>, threshold: f64) -> Self {
        Self {
            tracker,
            threshold,
            last_tool: DashMap::new(),
            stripes: (0..STRIPES).map(|_| parking_lot::Mutex::new(())).collect(),
        }
    }

    /// Score a tool invocation.
    ///
    /// Returns a value in `[0.0, 1.0]` where 1.0 means "never observed".
    /// Updates the per-session last-tool record after scoring.
    pub fn score_transition(&self, session_id: &str, server: &str, tool: &str) -> f64 {
        let current = format!("{server}:{tool}");

        // The read of the predecessor and the write of the successor are one
        // operation, held under a single entry guard. As a separate `get` and
        // `insert` they could interleave: two concurrent calls for one identity
        // both observed the same predecessor and both overwrote it, so a
        // sequence could be walked in parallel with every step scored as though
        // it were the first — which is precisely the sequence a detector exists
        // to notice.
        // Bounded. Every distinct identity leaves a predecessor behind, and
        // nothing reclaims one: `SessionLifecycle` was built to fire cleanup on
        // disconnect and is not wired to anything (recorded as its own issue),
        // and a stateless caller never disconnects because it never connected.
        // Without a ceiling this map is a memory-exhaustion vector reachable by
        // anyone who can present distinct credentials.
        //
        // Evicting an arbitrary entry costs that one caller its predecessor —
        // its next call scores as a first call — which is a far smaller loss
        // than unbounded growth, and is why the ceiling is generous.
        if self.last_tool.len() >= MAX_TRACKED_IDENTITIES
            && !self.last_tool.contains_key(session_id)
        {
            // The victim is chosen in its OWN statement so the iterator — and
            // the shard lock it holds — is dropped before the removal asks for
            // that same shard as a writer. Written as one `if let`, the guard
            // outlives the `remove` inside it and the thread deadlocks against
            // itself: the map is sharded, so this only bites once the ceiling
            // is actually reached, which no ordinary test run does.
            let victim = self.last_tool.iter().next().map(|e| e.key().clone());
            if let Some(victim) = victim {
                self.last_tool.remove(&victim);
            }
        }

        match self.last_tool.entry(session_id.to_string()) {
            dashmap::mapref::entry::Entry::Vacant(slot) => {
                // First tool for this identity — no prior context.
                slot.insert(current);
                0.5
            }
            dashmap::mapref::entry::Entry::Occupied(mut slot) => {
                let previous = slot.get().clone();
                // Ask the tracker for the likely successors of the previous tool.
                // min_confidence=0.0 and min_count=0 → return all successors.
                let predictions = self.tracker.predict_next(previous.as_str(), 0.0, 0);

                let score = if predictions.is_empty() {
                    // Cold start for this predecessor: no data → neutral.
                    0.5
                } else {
                    match predictions.iter().find(|p| p.tool == current) {
                        Some(p) => 1.0 - p.confidence,
                        None => 0.95, // Never seen after the previous tool.
                    }
                };
                slot.insert(current);
                score
            }
        }
    }

    /// The configured anomaly threshold.
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Set how many transitions a predecessor needs before its successors are
    /// scored (`firewall.anomaly_min_observations`).
    #[must_use]
    pub fn with_min_observations(self, _min_observations: u64) -> Self {
        self
    }

    /// Calls answered [`Observation::WarmingUp`] since start.
    #[allow(dead_code, reason = "red-first stub: the fix commit uses it")]
    pub(crate) fn warming_up_count(&self) -> u64 {
        0
    }

    /// New transitions not learned because the learned-pair map was full.
    #[allow(dead_code, reason = "red-first stub: the fix commit uses it")]
    pub(crate) fn pairs_dropped_count(&self) -> u64 {
        0
    }

    /// Hold `identity`'s scoring lock, so a test can prove a concurrent call
    /// for the same identity waits for it.
    /// The tracker this detector learns into.
    #[cfg(test)]
    pub(crate) fn tracker_for_test(&self) -> &TransitionTracker {
        &self.tracker
    }

    #[cfg(test)]
    pub(crate) fn hold_stripe(&self, _identity: &str) -> parking_lot::MutexGuard<'_, ()> {
        self.stripes[0].lock()
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

        assert!((never - 1.0).abs() < f64::EPSILON, "never-seen must score 1.0, got {never}");
        assert!(rare < never, "rare ({rare}) must score below never-seen ({never})");
    }

    #[test]
    fn cold_predecessor_is_warming_up() {
        // A first call has no predecessor, and a predecessor with 5 recorded
        // transitions is below the minimum of 20: neither is a score.
        let detector = AnomalyDetector::new(trained(5), 0.7).with_min_observations(20);
        assert_eq!(detector.observe(Some("id"), "srv", "tool_a"), Observation::WarmingUp);
        assert_eq!(detector.observe(Some("id"), "srv", "tool_b"), Observation::WarmingUp);
        assert_eq!(detector.warming_up_count(), 2);
    }

    #[test]
    fn warmup_counts_total_transitions() {
        // Warm-up counts every recorded transition out of the predecessor, not
        // distinct successors: 20 transitions to ONE successor are enough.
        let warm = AnomalyDetector::new(trained(20), 0.7).with_min_observations(20);
        warm.observe(Some("id"), "srv", "tool_a");
        assert!(
            matches!(warm.observe(Some("id"), "srv", "tool_b"), Observation::Scored(_)),
            "20 transitions out of tool_a meet a minimum of 20"
        );

        let cold = AnomalyDetector::new(trained(19), 0.7).with_min_observations(20);
        cold.observe(Some("id"), "srv", "tool_a");
        assert_eq!(cold.observe(Some("id"), "srv", "tool_b"), Observation::WarmingUp);
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
