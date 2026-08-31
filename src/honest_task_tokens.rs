// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Task-token comparison that is allowed to lose (MIK-6977).
//!
//! The README 89% figure is a *schema-only first-request* model: 100 tools ×
//! 150 tokens versus 16 meta-tools × 100 tokens, with extra discovery turns
//! counted as zero. This module counts those turns. Each extra turn reloads
//! the meta-surface, so a search-then-invoke path can cost more than loading
//! every tool definition once.
//!
//! Selection accuracy, end-to-end latency, and task success are **not**
//! produced here. Those need a live agent run.

/// Direct-connect tool-definition size used by `benchmarks/public_claims.json`.
pub const DIRECT_TOKENS_PER_TOOL: u64 = 150;
/// Meta-tool definition size used by `benchmarks/public_claims.json`.
pub const META_TOKENS_PER_TOOL: u64 = 100;
/// README benchmark meta-surface.
pub const README_META_TOOLS: u64 = 16;
/// Tool counts the ticket asked for.
pub const TOOL_COUNTS: [u64; 4] = [50, 100, 200, 500];
/// Default discovery path: `gateway_search_tools` then `gateway_invoke`.
pub const DEFAULT_EXTRA_TURNS: u64 = 2;

/// One row of eager-vs-meta task-token math.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskTokenRow {
    /// Permitted backend tools.
    pub n_tools: u64,
    /// Extra LLM turns on the meta path (0 = schema-only first request).
    pub extra_discovery_turns: u64,
    /// Eager: every tool definition loaded once.
    pub eager_tokens: u64,
    /// Meta: meta-surface × (1 + extra turns).
    pub meta_tokens: u64,
    /// `(1 - meta/eager) * 100`. Negative means the meta path lost.
    pub savings_percent: f64,
}

impl TaskTokenRow {
    /// True when the meta path used fewer tokens than eager load.
    pub fn meta_wins(&self) -> bool {
        self.meta_tokens < self.eager_tokens
    }
}

/// Compare eager load against a meta-surface that pays `extra_discovery_turns`.
///
/// A completed direct tool call is two requests (prompt + follow-up), each
/// still carrying every tool definition. The meta path is `1 + extra` requests
/// (prompt + search + invoke when extra is 2). Same completed-task length is
/// required on both sides so the comparison can lose.
pub fn task_tokens(n_tools: u64, extra_discovery_turns: u64) -> TaskTokenRow {
    let eager_turns = 2;
    let meta_turns = extra_discovery_turns.saturating_add(1);
    let eager_tokens = n_tools
        .saturating_mul(DIRECT_TOKENS_PER_TOOL)
        .saturating_mul(eager_turns);
    let meta_tokens = README_META_TOOLS
        .saturating_mul(META_TOKENS_PER_TOOL)
        .saturating_mul(meta_turns);
    let savings_percent = if eager_tokens == 0 {
        0.0
    } else {
        (1.0 - (meta_tokens as f64 / eager_tokens as f64)) * 100.0
    };
    TaskTokenRow {
        n_tools,
        extra_discovery_turns,
        eager_tokens,
        meta_tokens,
        savings_percent,
    }
}

/// Schema-only first-request row: one request each side, no extra turns.
pub fn schema_only_first_request(n_tools: u64) -> TaskTokenRow {
    let eager_tokens = n_tools.saturating_mul(DIRECT_TOKENS_PER_TOOL);
    let meta_tokens = README_META_TOOLS.saturating_mul(META_TOKENS_PER_TOOL);
    let savings_percent = if eager_tokens == 0 {
        0.0
    } else {
        (1.0 - (meta_tokens as f64 / eager_tokens as f64)) * 100.0
    };
    TaskTokenRow {
        n_tools,
        extra_discovery_turns: 0,
        eager_tokens,
        meta_tokens,
        savings_percent,
    }
}

/// Ticket matrix: 50/100/200/500 tools at the default extra-turn count.
pub fn default_matrix() -> [TaskTokenRow; 4] {
    TOOL_COUNTS.map(|n| task_tokens(n, DEFAULT_EXTRA_TURNS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_only_100_tools_matches_readme_model() {
        let row = schema_only_first_request(100);
        assert_eq!(row.eager_tokens, 15_000);
        assert_eq!(row.meta_tokens, 1_600);
        assert!((row.savings_percent - 89.333).abs() < 0.01);
        assert!(row.meta_wins());
    }

    #[test]
    fn extra_turns_can_make_meta_lose() {
        let win = task_tokens(100, 0);
        let lose = task_tokens(100, 20);
        assert!(win.meta_wins());
        assert!(!lose.meta_wins());
        assert!(lose.savings_percent < 0.0);
        assert!(lose.meta_tokens > lose.eager_tokens);
    }

    #[test]
    fn matrix_covers_the_four_tool_counts() {
        let rows = default_matrix();
        assert_eq!(rows[0].n_tools, 50);
        assert_eq!(rows[1].n_tools, 100);
        assert_eq!(rows[2].n_tools, 200);
        assert_eq!(rows[3].n_tools, 500);
        assert!(
            rows.iter()
                .all(|r| r.extra_discovery_turns == DEFAULT_EXTRA_TURNS)
        );
    }
}
