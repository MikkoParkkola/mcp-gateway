//! Smart search ranking based on usage frequency
//!
//! Ranks search results by combining text relevance with usage-based popularity.
//! Synonym expansion allows semantically related words to match with a slight
//! score discount (0.8×) relative to exact matches.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod scoring;

use scoring::score_text_relevance;
pub use scoring::{expand_synonyms, is_schema_field_match};

#[cfg(test)]
use scoring::{
    SYNONYM_MULTIPLIER, extract_tag_section, is_keyword_match, is_keyword_match_with_synonyms,
};

/// Search result with relevance score and adaptive ranking metadata.
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// Server name
    pub server: String,
    /// Tool name
    pub tool: String,
    /// Description
    pub description: String,
    /// Relevance score (higher = more relevant)
    pub score: f64,
    /// Coarse ranking signals used for scoring and explanations.
    pub signals: RankingSignals,
    /// Deterministic explanation for inclusion or downgrade.
    pub explanation: RankingExplanation,
    /// Exclusion reason when policy prefilters suppress the result.
    pub exclusion: Option<RankingExclusion>,
}

impl SearchResult {
    /// Create a search result with neutral non-relevance signals.
    #[must_use]
    pub fn new(
        server: impl Into<String>,
        tool: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            server: server.into(),
            tool: tool.into(),
            description: description.into(),
            score: 0.0,
            signals: RankingSignals::default(),
            explanation: RankingExplanation {
                included: true,
                reasons: Vec::new(),
            },
            exclusion: None,
        }
    }
}

/// Coarse ranking signals. Values are clamped to `0.0..=1.0` except
/// `usage_count`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RankingSignals {
    /// Text relevance computed from name, description, keywords, and schema.
    pub relevance: f64,
    /// Safety score. `0.0` suppresses the candidate.
    pub safety: f64,
    /// Trust score. Very low trust suppresses the candidate.
    pub trust: f64,
    /// Grant/authorization fit. `0.0` suppresses the candidate.
    pub grant: f64,
    /// Runtime health score. `0.0` suppresses the candidate.
    pub runtime_health: f64,
    /// Cost-efficiency score.
    pub cost_efficiency: f64,
    /// Latency score.
    pub latency: f64,
    /// Freshness score.
    pub freshness: f64,
    /// Local feedback boost derived from safe usage counters.
    pub user_feedback: f64,
    /// Local usage count used to compute feedback.
    pub usage_count: u64,
}

impl Default for RankingSignals {
    fn default() -> Self {
        Self {
            relevance: 0.0,
            safety: 1.0,
            trust: 1.0,
            grant: 1.0,
            runtime_health: 1.0,
            cost_efficiency: 1.0,
            latency: 1.0,
            freshness: 1.0,
            user_feedback: 0.0,
            usage_count: 0,
        }
    }
}

impl RankingSignals {
    fn from_json(value: &Value) -> Self {
        Self {
            safety: parse_safety_signal(value),
            trust: parse_numeric_signal(value, &["trust_score", "trust"], 1.0),
            grant: parse_grant_signal(value),
            runtime_health: parse_runtime_health_signal(value),
            cost_efficiency: parse_cost_efficiency_signal(value),
            latency: parse_latency_signal(value),
            freshness: parse_numeric_signal(value, &["freshness_score", "freshness"], 1.0),
            ..Self::default()
        }
    }

    fn multiplier(&self) -> f64 {
        // Relevance remains dominant. Non-text signals gently reorder safe
        // candidates without letting popularity override a poor intent match.
        let weighted = (self.safety * 0.24)
            + (self.trust * 0.18)
            + (self.grant * 0.18)
            + (self.runtime_health * 0.14)
            + (self.cost_efficiency * 0.10)
            + (self.latency * 0.06)
            + (self.freshness * 0.04)
            + (self.user_feedback.min(1.0) * 0.06);
        weighted.clamp(0.0, 1.25)
    }
}

/// Deterministic ranking explanation emitted with search results.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RankingExplanation {
    /// Whether the candidate survived policy prefilters.
    pub included: bool,
    /// Stable explanation reasons that do not include request payloads.
    pub reasons: Vec<String>,
}

/// Suppression category for policy prefilters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RankingExclusion {
    /// Exclusion kind.
    pub kind: RankingExclusionKind,
    /// Stable explanation reason.
    pub reason: String,
}

/// Coarse reason a candidate was suppressed before relevance ranking.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RankingExclusionKind {
    /// Unsafe metadata or risk marker.
    Unsafe,
    /// Missing or denied grant.
    Unauthorized,
    /// Unhealthy or disabled runtime.
    Unhealthy,
    /// Trust signal is below the safe threshold.
    Untrusted,
}

/// Search ranker with usage-based weighting
pub struct SearchRanker {
    /// Usage counts per tool (key = "server:tool")
    usage_counts: DashMap<String, AtomicU64>,
}

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
                score_text_relevance(&result.tool, &result.description, &query_lower, &words);

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
        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        results
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

/// Usage entry for serialization
#[derive(Debug, Serialize, Deserialize)]
struct UsageEntry {
    server: String,
    tool: String,
    count: u64,
}

/// Convert a JSON search result to a `SearchResult`
#[must_use]
pub fn json_to_search_result(value: &Value) -> Option<SearchResult> {
    let mut result = SearchResult::new(
        value.get("server")?.as_str()?,
        value.get("tool")?.as_str()?,
        value.get("description")?.as_str()?,
    );
    result.signals = RankingSignals::from_json(value);
    Some(result)
}

fn explanation_for(result: &SearchResult) -> RankingExplanation {
    let mut reasons = Vec::new();
    if result.signals.relevance > 0.0 {
        reasons.push("intent_match".to_string());
    } else {
        reasons.push("weak_intent_match".to_string());
    }
    if result.signals.safety >= 1.0 {
        reasons.push("safety_ok".to_string());
    }
    if result.signals.grant >= 1.0 {
        reasons.push("grant_ok".to_string());
    }
    if result.signals.trust < 0.75 {
        reasons.push("trust_downgraded".to_string());
    } else {
        reasons.push("trust_ok".to_string());
    }
    if result.signals.cost_efficiency < 0.75 {
        reasons.push("cost_downgraded".to_string());
    } else {
        reasons.push("cost_fit".to_string());
    }
    if result.signals.latency < 0.75 {
        reasons.push("latency_downgraded".to_string());
    } else {
        reasons.push("latency_fit".to_string());
    }
    if result.signals.user_feedback > 0.0 {
        reasons.push("local_feedback_boost".to_string());
    }

    RankingExplanation {
        included: true,
        reasons,
    }
}

fn exclusion_for(signals: &RankingSignals) -> Option<RankingExclusion> {
    if signals.safety <= 0.0 {
        return Some(RankingExclusion {
            kind: RankingExclusionKind::Unsafe,
            reason: "suppressed_unsafe".to_string(),
        });
    }
    if signals.grant <= 0.0 {
        return Some(RankingExclusion {
            kind: RankingExclusionKind::Unauthorized,
            reason: "suppressed_unauthorized".to_string(),
        });
    }
    if signals.runtime_health <= 0.0 {
        return Some(RankingExclusion {
            kind: RankingExclusionKind::Unhealthy,
            reason: "suppressed_unhealthy".to_string(),
        });
    }
    if signals.trust < 0.20 {
        return Some(RankingExclusion {
            kind: RankingExclusionKind::Untrusted,
            reason: "suppressed_untrusted".to_string(),
        });
    }
    None
}

fn parse_numeric_signal(value: &Value, keys: &[&str], default: f64) -> f64 {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_f64))
        .unwrap_or(default)
        .clamp(0.0, 1.0)
}

fn parse_safety_signal(value: &Value) -> f64 {
    if value
        .get("unsafe")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return 0.0;
    }
    if value
        .get("risk_level")
        .or_else(|| value.get("risk"))
        .and_then(Value::as_str)
        .is_some_and(|risk| matches!(risk, "high" | "critical" | "unsafe"))
    {
        return 0.0;
    }
    parse_numeric_signal(value, &["safety_score", "safety"], 1.0)
}

fn parse_grant_signal(value: &Value) -> f64 {
    if value.get("authorized").and_then(Value::as_bool) == Some(false) {
        return 0.0;
    }
    if value
        .get("grant_status")
        .or_else(|| value.get("grant"))
        .and_then(Value::as_str)
        .is_some_and(|grant| matches!(grant, "denied" | "missing" | "unauthorized"))
    {
        return 0.0;
    }
    parse_numeric_signal(value, &["grant_score", "grant"], 1.0)
}

fn parse_runtime_health_signal(value: &Value) -> f64 {
    if value
        .get("status")
        .or_else(|| value.get("runtime_status"))
        .and_then(Value::as_str)
        .is_some_and(|status| matches!(status, "disabled" | "unhealthy" | "down"))
    {
        return 0.0;
    }
    if value
        .get("health")
        .and_then(Value::as_str)
        .is_some_and(|health| matches!(health, "unhealthy" | "down"))
    {
        return 0.0;
    }
    parse_numeric_signal(value, &["runtime_health", "health_score"], 1.0)
}

fn parse_cost_efficiency_signal(value: &Value) -> f64 {
    if let Some(score) = value.get("cost_efficiency").and_then(Value::as_f64) {
        return score.clamp(0.0, 1.0);
    }
    if let Some(category) = value
        .get("cost_category")
        .or_else(|| value.get("cost_tier"))
        .and_then(Value::as_str)
    {
        return match category {
            "free" => 1.0,
            "low" => 0.85,
            "medium" => 0.65,
            "high" => 0.35,
            _ => 0.75,
        };
    }
    if let Some(cost) = value.get("cost_usd").and_then(Value::as_f64) {
        return (1.0 / (1.0 + (cost * 100.0))).clamp(0.0, 1.0);
    }
    1.0
}

fn parse_latency_signal(value: &Value) -> f64 {
    if let Some(score) = value.get("latency_score").and_then(Value::as_f64) {
        return score.clamp(0.0, 1.0);
    }
    if let Some(latency_ms) = value.get("latency_ms").and_then(Value::as_f64) {
        return (1.0 / (1.0 + (latency_ms / 1000.0))).clamp(0.0, 1.0);
    }
    1.0
}

#[cfg(test)]
mod tests;
