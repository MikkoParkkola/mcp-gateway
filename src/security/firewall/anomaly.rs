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

/// Per-session anomaly detector backed by transition probability data.
pub struct AnomalyDetector {
    tracker: Arc<TransitionTracker>,
    threshold: f64,
    /// Per-session last tool, used to compute P(current | last).
    ///
    /// Key: `session_id`, Value: last tool key (`"server:tool"`).
    last_tool: DashMap<String, String>,
}

impl AnomalyDetector {
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

        let score = match self.last_tool.get(session_id) {
            None => {
                // First tool in this session — no prior context.
                0.5
            }
            Some(prev) => {
                // Ask the tracker for the likely successors of the previous tool.
                // min_confidence=0.0 and min_count=0 → return all successors.
                let predictions = self.tracker.predict_next(prev.as_str(), 0.0, 0);

                if predictions.is_empty() {
                    // Cold start for this predecessor: no data → neutral.
                    0.5
                } else {
                    match predictions.iter().find(|p| p.tool == current) {
                        Some(p) => 1.0 - p.confidence,
                        None => 0.95, // Never seen after prev_tool.
                    }
                }
            }
        };

        // Update last_tool for this session.
        self.last_tool.insert(session_id.to_string(), current);

        score
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
