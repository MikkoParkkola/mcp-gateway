// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::{
    AtomicU64, DashMap, Ordering, Path, RankingEvalCase, RankingEvalCaseResult, RankingEvalReport,
    RankingExplanation, SearchRanker, SearchResult, UsageEntry, backend_name_score,
    baseline_top_tool, build_eval_case_result, exclusion_for, explanation_for,
    improvement_targets_for, json_to_search_result, ratio, score_text_relevance, sort_by_rank,
};

impl SearchRanker {
    /// Create a new ranker
    #[must_use]
    pub fn new() -> Self {
        Self {
            usage_counts: DashMap::new(),
        }
    }

    /// Record a tool usage
    pub fn record_use(&self, server: &str, tool: &str) {
        let key = format!("{server}:{tool}");
        self.usage_counts
            .entry(key)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get usage count for a tool
    #[must_use]
    pub fn usage_count(&self, server: &str, tool: &str) -> u64 {
        let key = format!("{server}:{tool}");
        self.usage_counts
            .get(&key)
            .map_or(0, |entry| entry.load(Ordering::Relaxed))
    }

    /// Rank search results by relevance and usage.
    ///
    /// # Scoring Algorithm
    ///
    /// `score = text_relevance * (1 + usage_factor)`
    ///
    /// Usage is **multiplicative** so it amplifies good matches but cannot
    /// promote irrelevant tools above highly relevant ones.
    ///
    /// Text relevance tiers (multi-word queries split on whitespace):
    /// - 15: all words match tool name
    /// - 10+2N: all N words found in name+description combined (2w=14, 3w=16)
    /// - 10: exact single-word name match
    /// - 6+2N: N query words match keyword tags in `[keywords: …]` (1=8, 2=10, 3=12)
    /// - 4+2N: N query words match schema field names in `[schema: …]` (1=6, 2=8, 3=10)
    /// - 3+2M: M of N words found in name+description (partial, 1/3=5, 2/3=7)
    /// - 6: single-word query matches a schema field name exactly
    /// - 5: name contains the full query as a substring
    /// - 4×share: the serving backend's name holds the query words (a word
    ///   matched through a synonym or abbreviation counts at the discount)
    /// - 2: description contains the full query as a substring
    ///
    /// Usage factor: `log2(usage_count + 1) * 0.15` (multiplicative)
    /// - 0 uses → ×1.0, 4 uses → ×1.35, 10 uses → ×1.52, 100 uses → ×2.0
    #[must_use]
    pub fn rank(&self, mut results: Vec<SearchResult>, query: &str) -> Vec<SearchResult> {
        let query_lower = query.to_lowercase();
        let words: Vec<&str> = query_lower.split_whitespace().collect();

        for result in &mut results {
            if let Some(exclusion) = exclusion_for(&result.signals) {
                result.exclusion = Some(exclusion.clone());
                result.explanation = RankingExplanation {
                    included: false,
                    reasons: vec![exclusion.reason],
                };
                result.score = 0.0;
                continue;
            }

            let text_relevance =
                score_text_relevance(&result.tool, &result.description, &query_lower, &words)
                    .max(backend_name_score(&result.server, &words));

            let usage = self.usage_count(&result.server, &result.tool);
            #[allow(clippy::cast_precision_loss)]
            let usage_factor = if usage > 0 {
                ((usage + 1) as f64).log2() * 0.15
            } else {
                0.0
            };

            result.signals.relevance = text_relevance;
            result.signals.usage_count = usage;
            result.signals.user_feedback = usage_factor;

            result.score = text_relevance * (1.0 + usage_factor) * result.signals.multiplier();
            result.explanation = explanation_for(result);
        }

        results.retain(|result| result.exclusion.is_none());
        sort_by_rank(results, &query_lower, &words)
    }

    /// Evaluate ranking quality against deterministic offline fixtures.
    ///
    /// The comparison baseline is text-only relevance with original-order
    /// tie-breaking. It intentionally ignores adaptive signals and policy
    /// prefilters so the report can quantify safety and trust lift.
    #[must_use]
    pub fn evaluate_offline(&self, cases: &[RankingEvalCase]) -> RankingEvalReport {
        let mut report = RankingEvalReport::empty(cases.len());

        for case in cases {
            let candidates: Vec<SearchResult> = case
                .candidates
                .iter()
                .filter_map(json_to_search_result)
                .collect();
            let invalid_candidates = case.candidates.len().saturating_sub(candidates.len());
            let baseline_top_tool = baseline_top_tool(&candidates, &case.query);
            let ranked = self.rank(candidates.clone(), &case.query);
            let actual_top_tool = ranked.first().map(|result| result.tool.clone());
            let filtered_candidates = candidates.len().saturating_sub(ranked.len());

            let case_result = build_eval_case_result(
                case,
                actual_top_tool,
                baseline_top_tool,
                filtered_candidates,
                invalid_candidates,
            );
            report.record_case(case_result);
        }

        report.finish()
    }

    /// Save usage counts to JSON file
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the file cannot be written.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let counts: Vec<UsageEntry> = self
            .usage_counts
            .iter()
            .map(|entry| {
                let parts: Vec<&str> = entry.key().split(':').collect();
                UsageEntry {
                    server: parts.first().unwrap_or(&"").to_string(),
                    tool: parts.get(1).unwrap_or(&"").to_string(),
                    count: entry.value().load(Ordering::Relaxed),
                }
            })
            .collect();

        let json = serde_json::to_string_pretty(&counts)?;
        std::fs::write(path, json)
    }

    /// Load usage counts from JSON file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or JSON is invalid.
    pub fn load(&self, path: &Path) -> std::io::Result<()> {
        let content = std::fs::read_to_string(path)?;
        let entries: Vec<UsageEntry> = serde_json::from_str(&content)?;

        for entry in entries {
            let key = format!("{}:{}", entry.server, entry.tool);
            self.usage_counts.insert(key, AtomicU64::new(entry.count));
        }

        Ok(())
    }

    /// Clear all usage counts
    pub fn clear(&self) {
        self.usage_counts.clear();
    }
}

impl Default for SearchRanker {
    fn default() -> Self {
        Self::new()
    }
}

impl RankingEvalReport {
    fn empty(case_count: usize) -> Self {
        Self {
            case_count,
            top1_hits: 0,
            baseline_top1_hits: 0,
            improvements_over_baseline: 0,
            regressions_vs_baseline: 0,
            filtered_candidates: 0,
            invalid_candidates: 0,
            top1_hit_rate: 0.0,
            baseline_top1_hit_rate: 0.0,
            cases: Vec::with_capacity(case_count),
            improvement_targets: Vec::new(),
        }
    }

    fn record_case(&mut self, case: RankingEvalCaseResult) {
        self.top1_hits += usize::from(case.top1_hit);
        self.baseline_top1_hits += usize::from(case.baseline_top1_hit);
        self.improvements_over_baseline += usize::from(case.top1_hit && !case.baseline_top1_hit);
        self.regressions_vs_baseline += usize::from(!case.top1_hit && case.baseline_top1_hit);
        self.filtered_candidates += case.filtered_candidates;
        self.invalid_candidates += case.invalid_candidates;
        self.cases.push(case);
    }

    fn finish(mut self) -> Self {
        self.top1_hit_rate = ratio(self.top1_hits, self.case_count);
        self.baseline_top1_hit_rate = ratio(self.baseline_top1_hits, self.case_count);
        self.improvement_targets = improvement_targets_for(&self);
        self
    }
}
