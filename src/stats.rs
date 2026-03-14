//! Usage statistics tracking for the gateway
//!
//! Tracks invocations, cache hits, tools discovered, cached token counts, and
//! calculates token/cost savings.

use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

/// Usage statistics for the gateway
#[derive(Default)]
pub struct UsageStats {
    /// Total tool invocations via `gateway_invoke`
    total_invocations: AtomicU64,
    /// Cache hits from response cache
    cache_hits: AtomicU64,
    /// Tools discovered via `gateway_search_tools`
    tools_discovered: AtomicU64,
    /// Per-tool usage counts (key = "server:tool")
    tool_usage: DashMap<String, AtomicU64>,
    /// Cumulative prompt-cached tokens returned by backends (key = server name)
    ///
    /// Populated from `usage.cache_read_input_tokens` (Anthropic) or
    /// `usage.prompt_tokens_details.cached_tokens` (`OpenAI`) in backend responses.
    cached_tokens_by_server: DashMap<String, AtomicU64>,
    /// Cumulative prompt-cached tokens per conversation/session (key = session ID)
    cached_tokens_by_session: DashMap<String, AtomicU64>,
}

impl UsageStats {
    /// Create new statistics tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a tool invocation
    pub fn record_invocation(&self, server: &str, tool: &str) {
        self.total_invocations.fetch_add(1, Ordering::Relaxed);
        let key = format!("{server}:{tool}");
        self.tool_usage
            .entry(key)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache hit
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record tools discovered in a search
    pub fn record_search(&self, count: u64) {
        self.tools_discovered.fetch_add(count, Ordering::Relaxed);
    }

    /// Record prompt-cached tokens returned by a backend response.
    ///
    /// `server` identifies the backend; `session_id` is optional and, when
    /// provided, accumulates per-conversation cache hit data.  `tokens == 0`
    /// is silently ignored to keep the counters clean.
    pub fn record_cached_tokens(&self, server: &str, session_id: Option<&str>, tokens: u64) {
        if tokens == 0 {
            return;
        }
        self.cached_tokens_by_server
            .entry(server.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(tokens, Ordering::Relaxed);

        if let Some(sid) = session_id {
            self.cached_tokens_by_session
                .entry(sid.to_string())
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(tokens, Ordering::Relaxed);
        }
    }

    /// Total cached tokens across all backends.
    pub fn total_cached_tokens(&self) -> u64 {
        self.cached_tokens_by_server
            .iter()
            .map(|e| e.value().load(Ordering::Relaxed))
            .sum()
    }

    /// Cached tokens for a specific server.
    pub fn cached_tokens_for_server(&self, server: &str) -> u64 {
        self.cached_tokens_by_server
            .get(server)
            .map_or(0, |e| e.load(Ordering::Relaxed))
    }

    /// Cached tokens for a specific session.
    pub fn cached_tokens_for_session(&self, session_id: &str) -> u64 {
        self.cached_tokens_by_session
            .get(session_id)
            .map_or(0, |e| e.load(Ordering::Relaxed))
    }

    /// Get usage count for a specific tool
    pub fn tool_usage(&self, server: &str, tool: &str) -> u64 {
        let key = format!("{server}:{tool}");
        self.tool_usage
            .get(&key)
            .map_or(0, |entry| entry.load(Ordering::Relaxed))
    }

    /// Get snapshot of current statistics
    pub fn snapshot(&self, total_backend_tools: usize) -> StatsSnapshot {
        let invocations = self.total_invocations.load(Ordering::Relaxed);
        let cache_hits = self.cache_hits.load(Ordering::Relaxed);
        let discovered = self.tools_discovered.load(Ordering::Relaxed);

        // Calculate token savings
        // Without gateway: each invocation would load ALL backend tools (~150 tokens each)
        // With gateway: 4 meta-tools are loaded instead
        // Savings = (total_backend_tools - 4) * 150 tokens * invocations
        let tokens_saved = if total_backend_tools > 4 {
            (total_backend_tools - 4) as u64 * 150 * invocations
        } else {
            0
        };

        // Get top tools
        let mut tool_counts: Vec<(String, u64)> = self
            .tool_usage
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().load(Ordering::Relaxed)))
            .collect();
        tool_counts.sort_by(|a, b| b.1.cmp(&a.1));
        tool_counts.truncate(10);

        let top_tools: Vec<TopTool> = tool_counts
            .into_iter()
            .map(|(name, count)| {
                let parts: Vec<&str> = name.split(':').collect();
                TopTool {
                    server: parts.first().unwrap_or(&"").to_string(),
                    tool: parts.get(1).unwrap_or(&"").to_string(),
                    count,
                }
            })
            .collect();

        #[allow(clippy::cast_precision_loss)]
        let cache_hit_rate = if invocations > 0 {
            cache_hits as f64 / invocations as f64
        } else {
            0.0
        };

        // Collect per-server cached token counts (sorted descending by tokens)
        let mut cached_tokens_by_server: Vec<CachedTokensEntry> = self
            .cached_tokens_by_server
            .iter()
            .map(|e| CachedTokensEntry {
                server: e.key().clone(),
                cached_tokens: e.value().load(Ordering::Relaxed),
            })
            .collect();
        cached_tokens_by_server.sort_by(|a, b| b.cached_tokens.cmp(&a.cached_tokens));

        let total_cached_tokens = cached_tokens_by_server
            .iter()
            .map(|e| e.cached_tokens)
            .sum();

        StatsSnapshot {
            invocations,
            cache_hits,
            cache_hit_rate,
            tools_discovered: discovered,
            tools_available: total_backend_tools,
            tokens_saved,
            top_tools,
            total_cached_tokens,
            cached_tokens_by_server,
        }
    }

    /// Calculate estimated cost savings
    #[allow(clippy::cast_precision_loss)]
    pub fn cost_savings(&self, total_backend_tools: usize, price_per_million: f64) -> f64 {
        let snapshot = self.snapshot(total_backend_tools);
        snapshot.tokens_saved as f64 * price_per_million / 1_000_000.0
    }
}

/// Snapshot of usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsSnapshot {
    /// Total invocations
    pub invocations: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache hit rate (0.0-1.0)
    pub cache_hit_rate: f64,
    /// Tools discovered via search
    pub tools_discovered: u64,
    /// Total tools available across backends
    pub tools_available: usize,
    /// Estimated tokens saved by using gateway
    pub tokens_saved: u64,
    /// Top 10 most-used tools
    pub top_tools: Vec<TopTool>,
    /// Total prompt-cached tokens observed across all backends
    pub total_cached_tokens: u64,
    /// Per-server prompt-cached token breakdown (sorted descending by token count)
    pub cached_tokens_by_server: Vec<CachedTokensEntry>,
}

impl StatsSnapshot {
    /// Calculate estimated cost savings at a given token price
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn estimated_savings_usd(&self, price_per_million: f64) -> f64 {
        self.tokens_saved as f64 * price_per_million / 1_000_000.0
    }
}

/// Top tool usage entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopTool {
    /// Server name
    pub server: String,
    /// Tool name
    pub tool: String,
    /// Usage count
    pub count: u64,
}

/// Per-server cached token entry in statistics snapshots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedTokensEntry {
    /// Backend server name
    pub server: String,
    /// Cumulative cached tokens from this backend
    pub cached_tokens: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_invocation() {
        let stats = UsageStats::new();
        stats.record_invocation("server1", "tool1");
        stats.record_invocation("server1", "tool1");
        stats.record_invocation("server2", "tool2");

        assert_eq!(stats.tool_usage("server1", "tool1"), 2);
        assert_eq!(stats.tool_usage("server2", "tool2"), 1);
        assert_eq!(stats.tool_usage("server3", "tool3"), 0);
    }

    #[test]
    fn test_snapshot() {
        let stats = UsageStats::new();
        stats.record_invocation("server1", "tool1");
        stats.record_invocation("server1", "tool1");
        stats.record_invocation("server2", "tool2");
        stats.record_cache_hit();
        stats.record_search(5);

        let snapshot = stats.snapshot(100);

        assert_eq!(snapshot.invocations, 3);
        assert_eq!(snapshot.cache_hits, 1);
        assert!((snapshot.cache_hit_rate - 0.333).abs() < 0.01);
        assert_eq!(snapshot.tools_discovered, 5);
        assert_eq!(snapshot.tools_available, 100);
        // (100 - 4) * 150 * 3 = 43,200
        assert_eq!(snapshot.tokens_saved, 43_200);
    }

    #[test]
    fn test_cost_savings() {
        let stats = UsageStats::new();
        for _ in 0..100 {
            stats.record_invocation("server1", "tool1");
        }

        // Price: $15/million input tokens (Claude Opus 4.6)
        let savings = stats.cost_savings(100, 15.0);

        // (100 - 4) * 150 * 100 = 1,440,000 tokens
        // 1,440,000 * $15 / 1,000,000 = $21.60
        assert!((savings - 21.6).abs() < 0.01);
    }

    #[test]
    fn test_top_tools() {
        let stats = UsageStats::new();
        stats.record_invocation("s1", "popular");
        stats.record_invocation("s1", "popular");
        stats.record_invocation("s1", "popular");
        stats.record_invocation("s2", "rare");

        let snapshot = stats.snapshot(50);

        assert_eq!(snapshot.top_tools.len(), 2);
        assert_eq!(snapshot.top_tools[0].tool, "popular");
        assert_eq!(snapshot.top_tools[0].count, 3);
        assert_eq!(snapshot.top_tools[1].tool, "rare");
        assert_eq!(snapshot.top_tools[1].count, 1);
    }

    #[test]
    fn test_no_savings_with_few_tools() {
        let stats = UsageStats::new();
        stats.record_invocation("s1", "t1");

        // Only 3 tools available, gateway has 4 meta-tools
        let snapshot = stats.snapshot(3);
        assert_eq!(snapshot.tokens_saved, 0);
    }

    #[test]
    fn test_default_impl() {
        let stats = UsageStats::default();
        let snapshot = stats.snapshot(100);
        assert_eq!(snapshot.invocations, 0);
        assert_eq!(snapshot.cache_hits, 0);
    }

    #[test]
    fn test_cache_hit_tracking() {
        let stats = UsageStats::new();
        stats.record_invocation("s1", "t1");
        stats.record_invocation("s1", "t1");
        stats.record_cache_hit();

        let snapshot = stats.snapshot(50);
        assert_eq!(snapshot.invocations, 2);
        assert_eq!(snapshot.cache_hits, 1);
        assert!((snapshot.cache_hit_rate - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_search_tracking() {
        let stats = UsageStats::new();
        stats.record_search(10);
        stats.record_search(5);

        let snapshot = stats.snapshot(100);
        assert_eq!(snapshot.tools_discovered, 15);
    }

    #[test]
    fn test_snapshot_estimated_savings() {
        let stats = UsageStats::new();
        stats.record_invocation("s1", "t1");

        let snapshot = stats.snapshot(100);
        let savings = snapshot.estimated_savings_usd(15.0);

        // (100 - 4) * 150 * 1 = 14,400 tokens
        // 14,400 * $15 / 1,000,000 = $0.216
        assert!((savings - 0.216).abs() < 0.001);
    }

    #[test]
    fn test_zero_invocations_cache_rate() {
        let stats = UsageStats::new();
        let snapshot = stats.snapshot(50);
        assert!(snapshot.cache_hit_rate < f64::EPSILON);
    }

    #[test]
    fn test_top_tools_sorting() {
        let stats = UsageStats::new();
        stats.record_invocation("s1", "rare");
        stats.record_invocation("s2", "common");
        stats.record_invocation("s2", "common");
        stats.record_invocation("s2", "common");
        stats.record_invocation("s3", "medium");
        stats.record_invocation("s3", "medium");

        let snapshot = stats.snapshot(50);

        assert_eq!(snapshot.top_tools.len(), 3);
        assert_eq!(snapshot.top_tools[0].tool, "common");
        assert_eq!(snapshot.top_tools[0].count, 3);
        assert_eq!(snapshot.top_tools[1].tool, "medium");
        assert_eq!(snapshot.top_tools[1].count, 2);
        assert_eq!(snapshot.top_tools[2].tool, "rare");
        assert_eq!(snapshot.top_tools[2].count, 1);
    }

    // ── cached_tokens ─────────────────────────────────────────────────

    #[test]
    fn record_cached_tokens_per_server() {
        // GIVEN: a fresh stats tracker
        let stats = UsageStats::new();

        // WHEN: recording cached tokens for two servers
        stats.record_cached_tokens("backend-a", None, 500);
        stats.record_cached_tokens("backend-a", None, 300);
        stats.record_cached_tokens("backend-b", None, 200);

        // THEN: per-server counts are correct
        assert_eq!(stats.cached_tokens_for_server("backend-a"), 800);
        assert_eq!(stats.cached_tokens_for_server("backend-b"), 200);
        assert_eq!(stats.cached_tokens_for_server("missing"), 0);
    }

    #[test]
    fn record_cached_tokens_per_session() {
        let stats = UsageStats::new();
        stats.record_cached_tokens("srv", Some("session-1"), 400);
        stats.record_cached_tokens("srv", Some("session-1"), 100);
        stats.record_cached_tokens("srv", Some("session-2"), 250);

        assert_eq!(stats.cached_tokens_for_session("session-1"), 500);
        assert_eq!(stats.cached_tokens_for_session("session-2"), 250);
        assert_eq!(stats.cached_tokens_for_session("unknown"), 0);
    }

    #[test]
    fn record_cached_tokens_zero_is_ignored() {
        let stats = UsageStats::new();
        stats.record_cached_tokens("srv", Some("s1"), 0);
        assert_eq!(stats.cached_tokens_for_server("srv"), 0);
        assert_eq!(stats.cached_tokens_for_session("s1"), 0);
    }

    #[test]
    fn total_cached_tokens_sums_all_servers() {
        let stats = UsageStats::new();
        stats.record_cached_tokens("a", None, 100);
        stats.record_cached_tokens("b", None, 200);
        stats.record_cached_tokens("c", None, 300);
        assert_eq!(stats.total_cached_tokens(), 600);
    }

    #[test]
    fn snapshot_includes_cached_tokens() {
        let stats = UsageStats::new();
        stats.record_cached_tokens("backend-x", None, 1000);
        stats.record_cached_tokens("backend-y", None, 500);

        let snap = stats.snapshot(50);
        assert_eq!(snap.total_cached_tokens, 1500);
        assert_eq!(snap.cached_tokens_by_server.len(), 2);
        // Sorted descending
        assert_eq!(snap.cached_tokens_by_server[0].server, "backend-x");
        assert_eq!(snap.cached_tokens_by_server[0].cached_tokens, 1000);
        assert_eq!(snap.cached_tokens_by_server[1].server, "backend-y");
        assert_eq!(snap.cached_tokens_by_server[1].cached_tokens, 500);
    }

    #[test]
    fn snapshot_empty_cached_tokens_when_none_recorded() {
        let stats = UsageStats::new();
        let snap = stats.snapshot(10);
        assert_eq!(snap.total_cached_tokens, 0);
        assert!(snap.cached_tokens_by_server.is_empty());
    }
}
