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

/// Per-session anomaly detector backed by transition probability data.
pub struct AnomalyDetector {
    tracker: Arc<TransitionTracker>,
    threshold: f64,
    /// Per-session last tool, used to compute P(current | last).
    ///
    /// Key: `session_id`, Value: last tool key (`"server:tool"`).
    last_tool: DashMap<String, String>,
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
}

impl Observation {
    /// The score, or `None` when nothing could be observed.
    #[must_use]
    pub const fn score(self) -> Option<f64> {
        match self {
            Self::Scored(value) => Some(value),
            Self::Unobservable => None,
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
            && let Some(victim) = self.last_tool.iter().next().map(|e| e.key().clone())
        {
            self.last_tool.remove(&victim);
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

        let detector = AnomalyDetector::new(Arc::clone(&tracker), 0.7);
        // Prime last_tool = "srv:tool_a"
        detector.score_transition("sess-test", "srv", "tool_a");
        // Score a tool that has NEVER followed tool_a.
        let score = detector.score_transition("sess-test", "srv", "totally_unknown");
        assert!(
            (score - 0.95).abs() < f64::EPSILON,
            "Expected 0.95 for never-seen transition, got {score}"
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
}
