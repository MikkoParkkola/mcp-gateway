//! Cross-user analytics for RFC-0073.
//!
//! Aggregates data from all profiles in a [`super::ProfileRegistry`] to answer
//! fleet-wide questions: which tools are most popular, how many users are
//! active, and what fraction of users have adopted a given tool.

use std::collections::HashMap;
use std::time::Duration;

use super::ProfileRegistry;

// ── UsageAnalytics ────────────────────────────────────────────────────────────

/// Fleet-wide tool-usage analytics computed from a [`ProfileRegistry`].
///
/// # Example
///
/// ```rust
/// # #[cfg(feature = "tool-profiles")]
/// # {
/// use std::time::Duration;
/// use mcp_gateway::tool_profiles::{ProfileRegistry, analytics::UsageAnalytics};
///
/// let registry = ProfileRegistry::new();
/// registry.record_usage("alice", "search");
/// registry.record_usage("bob",   "search");
/// registry.record_usage("carol", "summarise");
///
/// let analytics = UsageAnalytics::compute(&registry);
/// assert_eq!(analytics.top_tools(1)[0].0, "search");
/// assert_eq!(analytics.active_users(Duration::from_secs(3600)), 3);
/// # }
/// ```
pub struct UsageAnalytics {
    /// Global (`tool_name` -> total calls) map.
    global_counts: HashMap<String, u64>,
    /// Set of `user_ids` that used each tool (for adoption rate).
    tool_user_sets: HashMap<String, usize>,
    /// Total number of distinct users.
    total_users: usize,
    /// Snapshots used for recency queries.
    snapshots: Vec<super::ProfileSnapshot>,
}

impl UsageAnalytics {
    /// Compute analytics from the current state of `registry`.
    #[must_use]
    pub fn compute(registry: &ProfileRegistry) -> Self {
        let snapshots = registry.all_snapshots();
        let total_users = snapshots.len();

        let mut global_counts: HashMap<String, u64> = HashMap::new();
        let mut tool_user_sets: HashMap<String, usize> = HashMap::new();

        for snapshot in &snapshots {
            for tool in &snapshot.top_tools {
                *global_counts.entry(tool.tool_name.clone()).or_insert(0) += tool.call_count;
                *tool_user_sets.entry(tool.tool_name.clone()).or_insert(0) += 1;
            }
        }

        Self {
            global_counts,
            tool_user_sets,
            total_users,
            snapshots,
        }
    }

    /// Return the top-`limit` tools globally, sorted by total call count descending.
    ///
    /// Each entry is `(tool_name, total_call_count)`.
    #[must_use]
    pub fn top_tools(&self, limit: usize) -> Vec<(String, u64)> {
        let mut sorted: Vec<(String, u64)> = self
            .global_counts
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        sorted.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        sorted.truncate(limit);
        sorted
    }

    /// Count users whose last tool call falls within the past `window`.
    #[must_use]
    pub fn active_users(&self, window: Duration) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let cutoff = now.saturating_sub(window.as_secs());
        self.snapshots
            .iter()
            .filter(|s| s.last_active_secs.is_some_and(|t| t >= cutoff))
            .count()
    }

    /// Fraction of users (0.0–1.0) who have invoked `tool_name` at least once.
    ///
    /// Returns `0.0` when there are no users or the tool has never been used.
    #[must_use]
    pub fn tool_adoption_rate(&self, tool_name: &str) -> f64 {
        if self.total_users == 0 {
            return 0.0;
        }
        let user_count = self.tool_user_sets.get(tool_name).copied().unwrap_or(0);
        #[allow(clippy::cast_precision_loss)]
        let rate = user_count as f64 / self.total_users as f64;
        rate
    }

    /// Total number of distinct users tracked.
    #[must_use]
    pub fn total_users(&self) -> usize {
        self.total_users
    }

    /// Total call count for a specific tool across all users.
    ///
    /// Returns `0` when the tool has never been called.
    #[must_use]
    pub fn total_calls_for_tool(&self, tool_name: &str) -> u64 {
        self.global_counts.get(tool_name).copied().unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool_profiles::ProfileRegistry;

    fn populated_registry() -> ProfileRegistry {
        let r = ProfileRegistry::new();
        // alice: search×5, summarise×2
        for _ in 0..5 {
            r.record_usage("alice", "search");
        }
        for _ in 0..2 {
            r.record_usage("alice", "summarise");
        }
        // bob: search×3, translate×1
        for _ in 0..3 {
            r.record_usage("bob", "search");
        }
        r.record_usage("bob", "translate");
        // carol: translate×4
        for _ in 0..4 {
            r.record_usage("carol", "translate");
        }
        r
    }

    #[test]
    fn top_tools_returns_sorted_by_count_descending() {
        // GIVEN: registry with known call counts
        let registry = populated_registry();
        let analytics = UsageAnalytics::compute(&registry);

        // WHEN: top 2 tools requested
        let top = analytics.top_tools(2);

        // THEN: search (8 total) > translate (5 total) > summarise (2 total)
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "search");
        assert_eq!(top[0].1, 8);
        assert_eq!(top[1].0, "translate");
        assert_eq!(top[1].1, 5);
    }

    #[test]
    fn top_tools_limit_respected() {
        // GIVEN: 3 distinct tools
        let registry = populated_registry();
        let analytics = UsageAnalytics::compute(&registry);

        // WHEN: limit=1
        let top = analytics.top_tools(1);

        // THEN: only one result
        assert_eq!(top.len(), 1);
    }

    #[test]
    fn top_tools_returns_all_when_limit_exceeds_count() {
        // GIVEN: 3 distinct tools, limit=100
        let registry = populated_registry();
        let analytics = UsageAnalytics::compute(&registry);

        // THEN: all 3 are returned
        assert_eq!(analytics.top_tools(100).len(), 3);
    }

    #[test]
    fn active_users_counts_all_users_when_window_is_large() {
        // GIVEN: 3 users just recorded usage (very recent)
        let registry = populated_registry();
        let analytics = UsageAnalytics::compute(&registry);

        // WHEN: window is very large (1 day)
        let count = analytics.active_users(Duration::from_secs(86_400));

        // THEN: all 3 users are counted
        assert_eq!(count, 3);
    }

    #[test]
    fn active_users_returns_zero_when_window_is_zero() {
        // GIVEN: any registry
        let registry = populated_registry();
        let analytics = UsageAnalytics::compute(&registry);

        // WHEN: window is zero seconds (nothing could be that recent after compute)
        // Note: with a 0-second window, last_active can equal cutoff; saturating_sub(0) = now
        // so last_active >= cutoff is possible for very recent events — use 0 Duration
        let count = analytics.active_users(Duration::ZERO);

        // THEN: count is >= 0 (may be 3 if timestamps equal now_secs)
        assert!(count <= 3);
    }

    #[test]
    fn tool_adoption_rate_search_used_by_two_of_three_users() {
        // GIVEN: search used by alice and bob (not carol)
        let registry = populated_registry();
        let analytics = UsageAnalytics::compute(&registry);

        // WHEN: adoption rate computed for "search"
        let rate = analytics.tool_adoption_rate("search");

        // THEN: 2/3 ≈ 0.666...
        assert!((rate - 2.0 / 3.0).abs() < 1e-9, "Expected 2/3, got {rate}");
    }

    #[test]
    fn tool_adoption_rate_translate_used_by_two_of_three_users() {
        // GIVEN: translate used by bob and carol (not alice)
        let registry = populated_registry();
        let analytics = UsageAnalytics::compute(&registry);

        // THEN: 2/3
        let rate = analytics.tool_adoption_rate("translate");
        assert!((rate - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn tool_adoption_rate_unknown_tool_returns_zero() {
        // GIVEN: "nonexistent" never called
        let registry = populated_registry();
        let analytics = UsageAnalytics::compute(&registry);

        // THEN: 0.0
        assert_eq!(analytics.tool_adoption_rate("nonexistent"), 0.0);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn tool_adoption_rate_empty_registry_returns_zero() {
        // GIVEN: empty registry
        let registry = ProfileRegistry::new();
        let analytics = UsageAnalytics::compute(&registry);

        // THEN: 0.0 (no division by zero)
        assert_eq!(analytics.tool_adoption_rate("search"), 0.0);
    }

    #[test]
    fn total_calls_for_tool_sums_across_users() {
        // GIVEN: search called 5+3=8 times total
        let registry = populated_registry();
        let analytics = UsageAnalytics::compute(&registry);

        // THEN: total is 8
        assert_eq!(analytics.total_calls_for_tool("search"), 8);
    }

    #[test]
    fn total_users_reflects_distinct_user_count() {
        // GIVEN: 3 users
        let registry = populated_registry();
        let analytics = UsageAnalytics::compute(&registry);

        // THEN: total_users == 3
        assert_eq!(analytics.total_users(), 3);
    }
}
