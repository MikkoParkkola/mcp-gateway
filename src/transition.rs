//! Predictive tool prefetch via invocation sequence tracking.
//!
//! Tracks which tools are called after which within a session, learns
//! transition probabilities, and predicts likely next tools to invoke.
//!
//! # Design
//!
//! - `TransitionTracker` owns all state (thread-safe via `DashMap` + `parking_lot`).
//! - `record_transition(session_id, tool)` updates per-session "last tool" and
//!   increments the transition counter for `last → current`.
//! - `predict_next(tool, min_confidence, min_count)` returns candidates whose
//!   observed frequency clears both thresholds, sorted by descending confidence.
//! - Save/load follows the same pattern as [`crate::ranking::SearchRanker`].
//!
//! # Thresholds
//!
//! Predictions are only emitted when a candidate satisfies **both**:
//! - `count ≥ min_count` — prevents noise from single observations
//! - `confidence ≥ min_confidence` — expressed as a fraction (0.0–1.0)

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

// ============================================================================
// Public types
// ============================================================================

/// A predicted next tool with its confidence score.
#[derive(Debug, Clone, PartialEq)]
pub struct Prediction {
    /// Fully-qualified tool identifier (`"server:tool"`)
    pub tool: String,
    /// Confidence in the range `[0.0, 1.0]`
    pub confidence: f64,
}

// ============================================================================
// TransitionTracker
// ============================================================================

/// Thread-safe tracker for tool invocation sequence learning.
///
/// Internally uses two `DashMap` layers:
/// - outer key: `"from_tool"` (the tool just invoked)
/// - inner key: `"to_tool"` (the tool invoked next)
/// - value: `AtomicU64` transition count
///
/// Per-session "last invoked tool" is tracked in a separate `DashMap`
/// with `Mutex<Option<String>>` values so sessions are independent.
pub struct TransitionTracker {
    /// `from_tool -> (to_tool -> count)`
    transitions: DashMap<String, DashMap<String, AtomicU64>>,
    /// `session_id -> last_invoked_tool`
    last_per_session: DashMap<String, Mutex<Option<String>>>,
}

impl TransitionTracker {
    /// Create a new, empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            transitions: DashMap::new(),
            last_per_session: DashMap::new(),
        }
    }

    /// Record a tool invocation for a session.
    ///
    /// If the session has a previous tool, increments the `previous → tool`
    /// transition counter. Always updates the session's "last tool".
    ///
    /// # Arguments
    /// * `session_id` — opaque session identifier
    /// * `tool` — fully-qualified tool key, e.g. `"server:tool_name"`
    pub fn record_transition(&self, session_id: &str, tool: &str) {
        // Get-or-create the session slot, then swap the last-tool under the lock.
        let previous = {
            let entry = self
                .last_per_session
                .entry(session_id.to_string())
                .or_insert_with(|| Mutex::new(None));
            let mut guard = entry.value().lock();
            guard.replace(tool.to_string())
        };

        // Record the transition if there was a previous tool.
        if let Some(from) = previous {
            let inner = self
                .transitions
                .entry(from)
                .or_default();
            inner
                .entry(tool.to_string())
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Predict the most likely next tools after `from_tool`.
    ///
    /// Returns candidates sorted by descending confidence where both
    /// `count ≥ min_count` and `confidence ≥ min_confidence`.
    ///
    /// Runs in **O(k)** where k is the number of distinct successors of
    /// `from_tool` — typically very small (< 20).
    ///
    /// # Arguments
    /// * `from_tool` — the tool just invoked
    /// * `min_confidence` — minimum fraction threshold (e.g. `0.30` for 30 %)
    /// * `min_count` — minimum absolute occurrence count (e.g. `3`)
    #[must_use]
    pub fn predict_next(
        &self,
        from_tool: &str,
        min_confidence: f64,
        min_count: u64,
    ) -> Vec<Prediction> {
        let Some(successors) = self.transitions.get(from_tool) else {
            return Vec::new();
        };

        let total: u64 = successors
            .iter()
            .map(|e| e.value().load(Ordering::Relaxed))
            .sum();

        if total == 0 {
            return Vec::new();
        }

        #[allow(clippy::cast_precision_loss)]
        let mut predictions: Vec<Prediction> = successors
            .iter()
            .filter_map(|entry| {
                let count = entry.value().load(Ordering::Relaxed);
                let confidence = count as f64 / total as f64;
                if count >= min_count && confidence >= min_confidence {
                    Some(Prediction {
                        tool: entry.key().clone(),
                        confidence,
                    })
                } else {
                    None
                }
            })
            .collect();

        // Deterministic descending sort by confidence, then tool name for ties.
        predictions.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.tool.cmp(&b.tool))
        });

        predictions
    }

    /// Total number of recorded transitions (sum across all from-tools).
    #[must_use]
    pub fn total_transitions(&self) -> u64 {
        self.transitions
            .iter()
            .flat_map(|outer| {
                outer
                    .value()
                    .iter()
                    .map(|inner| inner.value().load(Ordering::Relaxed))
                    .collect::<Vec<_>>()
            })
            .sum()
    }

    /// Save transition data to a JSON file.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the file cannot be written.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let entries: Vec<TransitionEntry> = self
            .transitions
            .iter()
            .flat_map(|outer| {
                let from = outer.key().clone();
                outer
                    .value()
                    .iter()
                    .map(move |inner| TransitionEntry {
                        from: from.clone(),
                        to: inner.key().clone(),
                        count: inner.value().load(Ordering::Relaxed),
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        let json = serde_json::to_string_pretty(&entries)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }

    /// Load transition data from a JSON file.
    ///
    /// Merges the loaded data with any existing in-memory state — useful for
    /// hot-reloading without losing in-flight session data.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or JSON is invalid.
    pub fn load(&self, path: &Path) -> std::io::Result<()> {
        let content = std::fs::read_to_string(path)?;
        let entries: Vec<TransitionEntry> = serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        for entry in entries {
            let inner = self
                .transitions
                .entry(entry.from)
                .or_default();
            inner
                .entry(entry.to)
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(entry.count, Ordering::Relaxed);
        }

        Ok(())
    }
}

impl Default for TransitionTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Serialization helpers (private)
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
struct TransitionEntry {
    from: String,
    to: String,
    count: u64,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    // ── record_transition ────────────────────────────────────────────────

    #[test]
    fn record_transition_first_call_has_no_predecessor() {
        // GIVEN: a fresh tracker and a new session
        // WHEN: recording the first tool invocation
        // THEN: no transitions are recorded (nothing to chain from)
        let tracker = TransitionTracker::new();
        tracker.record_transition("session-1", "s1:tool_a");

        assert_eq!(tracker.total_transitions(), 0);
    }

    #[test]
    fn record_transition_second_call_creates_one_transition() {
        // GIVEN: session with one prior invocation
        // WHEN: a second tool is invoked
        // THEN: exactly one A→B transition is recorded
        let tracker = TransitionTracker::new();
        tracker.record_transition("s", "s1:tool_a");
        tracker.record_transition("s", "s1:tool_b");

        assert_eq!(tracker.total_transitions(), 1);
        let preds = tracker.predict_next("s1:tool_a", 0.0, 1);
        assert_eq!(preds.len(), 1);
        assert_eq!(preds[0].tool, "s1:tool_b");
        assert!((preds[0].confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn record_transition_repeated_pair_increments_count() {
        // GIVEN: the same A→B pair observed three times
        // WHEN: predicting next after A
        // THEN: count is 3 and confidence is 1.0
        let tracker = TransitionTracker::new();
        for _ in 0..3 {
            tracker.record_transition("s", "s1:tool_a");
            tracker.record_transition("s", "s1:tool_b");
        }

        let preds = tracker.predict_next("s1:tool_a", 0.0, 1);
        assert_eq!(preds.len(), 1);
        assert_eq!(preds[0].tool, "s1:tool_b");
        // 3/3 = 1.0 — but the session ends on "s1:tool_b" so only 3 A→B are recorded
        assert!((preds[0].confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn record_transition_multiple_successors_tracked_independently() {
        // GIVEN: A→B twice, A→C once (interleaved via session resets)
        // WHEN: predicting next after A
        // THEN: B confidence = 2/3, C confidence = 1/3
        let tracker = TransitionTracker::new();

        // Session 1: A→B
        tracker.record_transition("s1", "s1:tool_a");
        tracker.record_transition("s1", "s1:tool_b");

        // Session 2: A→B
        tracker.record_transition("s2", "s1:tool_a");
        tracker.record_transition("s2", "s1:tool_b");

        // Session 3: A→C
        tracker.record_transition("s3", "s1:tool_a");
        tracker.record_transition("s3", "s1:tool_c");

        let preds = tracker.predict_next("s1:tool_a", 0.0, 1);
        assert_eq!(preds.len(), 2);
        assert_eq!(preds[0].tool, "s1:tool_b");
        assert!((preds[0].confidence - 2.0 / 3.0).abs() < 0.001);
        assert_eq!(preds[1].tool, "s1:tool_c");
        assert!((preds[1].confidence - 1.0 / 3.0).abs() < 0.001);
    }

    #[test]
    fn record_transition_different_sessions_are_independent() {
        // GIVEN: two sessions starting with different tools
        // WHEN: both sessions call tool_b second
        // THEN: transitions are attributed to each session's own "last tool"
        let tracker = TransitionTracker::new();

        tracker.record_transition("s1", "s1:tool_a");
        tracker.record_transition("s2", "s1:tool_x");
        tracker.record_transition("s1", "s1:tool_b"); // A→B
        tracker.record_transition("s2", "s1:tool_b"); // X→B

        let preds_a = tracker.predict_next("s1:tool_a", 0.0, 1);
        assert_eq!(preds_a.len(), 1);
        assert_eq!(preds_a[0].tool, "s1:tool_b");

        let preds_x = tracker.predict_next("s1:tool_x", 0.0, 1);
        assert_eq!(preds_x.len(), 1);
        assert_eq!(preds_x[0].tool, "s1:tool_b");
    }

    // ── predict_next ─────────────────────────────────────────────────────

    #[test]
    fn predict_next_returns_empty_for_unknown_tool() {
        // GIVEN: tracker with no data
        // WHEN: predicting next for an unknown tool
        // THEN: empty result (no panic)
        let tracker = TransitionTracker::new();
        let preds = tracker.predict_next("nonexistent:tool", 0.30, 3);
        assert!(preds.is_empty());
    }

    #[test]
    fn predict_next_filters_by_min_count() {
        // GIVEN: A→B seen once (below min_count = 3)
        // WHEN: predicting with min_count = 3
        // THEN: no predictions returned
        let tracker = TransitionTracker::new();
        tracker.record_transition("s", "s1:tool_a");
        tracker.record_transition("s", "s1:tool_b");

        let preds = tracker.predict_next("s1:tool_a", 0.0, 3);
        assert!(preds.is_empty());
    }

    #[test]
    fn predict_next_filters_by_min_confidence() {
        // GIVEN: A→B once, A→C four times (total 5), B confidence = 0.20
        // WHEN: predicting with min_confidence = 0.30
        // THEN: only C appears (confidence 0.80)
        let tracker = TransitionTracker::new();

        tracker.record_transition("s1", "s1:tool_a");
        tracker.record_transition("s1", "s1:tool_b"); // A→B ×1

        for _ in 0..4 {
            tracker.record_transition("s2", "s1:tool_a");
            tracker.record_transition("s2", "s1:tool_c"); // A→C ×4
        }

        let preds = tracker.predict_next("s1:tool_a", 0.30, 1);
        assert_eq!(preds.len(), 1);
        assert_eq!(preds[0].tool, "s1:tool_c");
        assert!((preds[0].confidence - 0.80).abs() < 0.001);
    }

    #[test]
    fn predict_next_satisfies_both_thresholds() {
        // GIVEN: default thresholds 30% confidence + 3 min occurrences
        // A→B: 8 times out of 10 total → confidence 0.80, count 8 → PASSES
        // A→C: 2 times out of 10 total → confidence 0.20, count 2 → FAILS BOTH
        // WHEN: predicting with defaults
        // THEN: only B is returned
        let tracker = TransitionTracker::new();

        for _ in 0..8 {
            tracker.record_transition("sx", "s1:tool_a");
            tracker.record_transition("sx", "s1:tool_b");
        }
        for _ in 0..2 {
            tracker.record_transition("sy", "s1:tool_a");
            tracker.record_transition("sy", "s1:tool_c");
        }

        let preds = tracker.predict_next("s1:tool_a", 0.30, 3);
        assert_eq!(preds.len(), 1);
        assert_eq!(preds[0].tool, "s1:tool_b");
    }

    #[test]
    fn predict_next_is_sorted_by_descending_confidence() {
        // GIVEN: A→B 6×, A→C 3×, A→D 1× (all clear min_count=1, min_confidence=0)
        // WHEN: predicting
        // THEN: order is B (0.60), C (0.30), D (0.10)
        let tracker = TransitionTracker::new();

        for _ in 0..6 {
            tracker.record_transition("sx", "s1:tool_a");
            tracker.record_transition("sx", "s1:tool_b");
        }
        for _ in 0..3 {
            tracker.record_transition("sy", "s1:tool_a");
            tracker.record_transition("sy", "s1:tool_c");
        }
        tracker.record_transition("sz", "s1:tool_a");
        tracker.record_transition("sz", "s1:tool_d");

        let preds = tracker.predict_next("s1:tool_a", 0.0, 1);
        assert_eq!(preds.len(), 3);
        assert!(preds[0].confidence >= preds[1].confidence);
        assert!(preds[1].confidence >= preds[2].confidence);
        assert_eq!(preds[0].tool, "s1:tool_b");
    }

    #[test]
    fn predict_next_tie_broken_by_tool_name_alphabetically() {
        // GIVEN: A→B 5×, A→C 5× (equal confidence)
        // WHEN: predicting
        // THEN: B comes before C (alphabetical tiebreak)
        let tracker = TransitionTracker::new();

        for _ in 0..5 {
            tracker.record_transition("s1", "s1:tool_a");
            tracker.record_transition("s1", "s1:tool_b");
        }
        for _ in 0..5 {
            tracker.record_transition("s2", "s1:tool_a");
            tracker.record_transition("s2", "s1:tool_c");
        }

        let preds = tracker.predict_next("s1:tool_a", 0.0, 1);
        assert_eq!(preds.len(), 2);
        assert_eq!(preds[0].tool, "s1:tool_b");
        assert_eq!(preds[1].tool, "s1:tool_c");
    }

    // ── cold start / edge cases ──────────────────────────────────────────

    #[test]
    fn predict_next_cold_start_no_data_returns_empty() {
        // GIVEN: brand-new tracker
        // WHEN: predicting for any tool
        // THEN: always empty, no panic
        let tracker = TransitionTracker::new();
        assert!(tracker.predict_next("any:tool", 0.30, 3).is_empty());
    }

    #[test]
    fn record_transition_single_session_single_call_no_transitions() {
        // GIVEN: only one call in a session (no chain possible)
        // THEN: transitions = 0 and predictions are empty
        let tracker = TransitionTracker::new();
        tracker.record_transition("session-x", "s1:lonely_tool");

        assert_eq!(tracker.total_transitions(), 0);
        assert!(tracker
            .predict_next("s1:lonely_tool", 0.0, 1)
            .is_empty());
    }

    // ── persistence ──────────────────────────────────────────────────────

    #[test]
    fn save_and_load_round_trips_transition_counts() {
        // GIVEN: tracker with A→B×5, A→C×2
        let tracker = TransitionTracker::new();
        for _ in 0..5 {
            tracker.record_transition("s1", "s1:tool_a");
            tracker.record_transition("s1", "s1:tool_b");
        }
        for _ in 0..2 {
            tracker.record_transition("s2", "s1:tool_a");
            tracker.record_transition("s2", "s1:tool_c");
        }

        let file = NamedTempFile::new().unwrap();
        tracker.save(file.path()).unwrap();

        // WHEN: loading into a fresh tracker
        let loaded = TransitionTracker::new();
        loaded.load(file.path()).unwrap();

        // THEN: predictions match original
        let preds = loaded.predict_next("s1:tool_a", 0.0, 1);
        assert_eq!(preds.len(), 2);
        assert_eq!(preds[0].tool, "s1:tool_b");
        assert!((preds[0].confidence - 5.0 / 7.0).abs() < 0.001);
        assert_eq!(preds[1].tool, "s1:tool_c");
        assert!((preds[1].confidence - 2.0 / 7.0).abs() < 0.001);
    }

    #[test]
    fn load_merges_with_existing_data() {
        // GIVEN: in-memory A→B×3 and file with A→B×2 (total should be 5)
        let tracker = TransitionTracker::new();
        for _ in 0..3 {
            tracker.record_transition("s", "s1:tool_a");
            tracker.record_transition("s", "s1:tool_b");
        }

        // Save the file-based data separately
        let file_tracker = TransitionTracker::new();
        for _ in 0..2 {
            file_tracker.record_transition("s", "s1:tool_a");
            file_tracker.record_transition("s", "s1:tool_b");
        }
        let file = NamedTempFile::new().unwrap();
        file_tracker.save(file.path()).unwrap();

        // Load into original tracker (merge)
        tracker.load(file.path()).unwrap();

        // WHEN: predicting after merge
        let preds = tracker.predict_next("s1:tool_a", 0.0, 1);
        assert_eq!(preds.len(), 1);
        // 3 in-memory + 2 from file = 5, confidence 5/5 = 1.0
        assert!((preds[0].confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn save_empty_tracker_produces_valid_json() {
        // GIVEN: tracker with no data
        // WHEN: saving
        // THEN: writes valid (empty array) JSON
        let tracker = TransitionTracker::new();
        let file = NamedTempFile::new().unwrap();
        tracker.save(file.path()).unwrap();

        let content = std::fs::read_to_string(file.path()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 0);
    }

    #[test]
    fn load_empty_file_is_a_no_op() {
        // GIVEN: empty JSON array on disk
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "[]").unwrap();

        let tracker = TransitionTracker::new();
        tracker.load(file.path()).unwrap();

        assert_eq!(tracker.total_transitions(), 0);
    }

    #[test]
    fn total_transitions_counts_all_edges() {
        // GIVEN: three sessions with interleaved tool calls.
        //
        // Session "sx" (2 iterations of a→b):
        //   iter1: record(a) → last=a; record(b) → a→b×1, last=b
        //   iter2: record(a) → b→a×1, last=a; record(b) → a→b×2, last=b
        //   edges from sx: a→b×2, b→a×1  → 3 counted edges
        //
        // Session "sy":
        //   record(a) → last=a; record(c) → a→c×1, last=c
        //   edges from sy: a→c×1            → 1 counted edge
        //
        // Session "sz" (3 iterations of x→y):
        //   iter1: record(x) → last=x; record(y) → x→y×1, last=y
        //   iter2: record(x) → y→x×1, last=x; record(y) → x→y×2, last=y
        //   iter3: record(x) → y→x×2, last=x; record(y) → x→y×3, last=y
        //   edges from sz: x→y×3, y→x×2   → 5 counted edges
        //
        // Total: 3 + 1 + 5 = 9
        let tracker = TransitionTracker::new();
        for _ in 0..2 {
            tracker.record_transition("sx", "t:a");
            tracker.record_transition("sx", "t:b");
        }
        tracker.record_transition("sy", "t:a");
        tracker.record_transition("sy", "t:c");
        for _ in 0..3 {
            tracker.record_transition("sz", "t:x");
            tracker.record_transition("sz", "t:y");
        }

        assert_eq!(tracker.total_transitions(), 9);
    }
}
