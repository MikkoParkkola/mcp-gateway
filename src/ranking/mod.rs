// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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

mod rank_key;
mod ranker;
mod scoring;

use rank_key::sort_by_rank;

pub use scoring::{expand_synonyms, is_schema_field_match};
// In-crate only: the gateway filter needs it, the public surface does not.
pub(crate) use scoring::expand_abbreviations;
use scoring::{backend_name_score, score_text_relevance};

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
    /// Risk-fit score where `1.0` means low risk and `0.0` suppresses the candidate.
    pub risk: f64,
    /// Trust score. Very low trust suppresses the candidate.
    pub trust: f64,
    /// Grant/authorization fit. `0.0` suppresses the candidate.
    pub grant: f64,
    /// Policy fit. `0.0` suppresses the candidate.
    pub policy_fit: f64,
    /// Permission fit derived from identity, scope, and grant metadata.
    pub permission_fit: f64,
    /// Runtime health score. `0.0` suppresses the candidate.
    pub runtime_health: f64,
    /// Cost-efficiency score.
    pub cost_efficiency: f64,
    /// Latency score.
    pub latency: f64,
    /// Historical success-rate score.
    pub success_rate: f64,
    /// Freshness score.
    pub freshness: f64,
    /// User preference score.
    pub user_preference: f64,
    /// Organization preference score.
    pub organization_preference: f64,
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
            risk: 1.0,
            trust: 1.0,
            grant: 1.0,
            policy_fit: 1.0,
            permission_fit: 1.0,
            runtime_health: 1.0,
            cost_efficiency: 1.0,
            latency: 1.0,
            success_rate: 1.0,
            freshness: 1.0,
            user_preference: 1.0,
            organization_preference: 1.0,
            user_feedback: 0.0,
            usage_count: 0,
        }
    }
}

impl RankingSignals {
    pub(crate) fn from_json(value: &Value) -> Self {
        let grant = parse_grant_signal(value);
        Self {
            safety: parse_safety_signal(value),
            risk: parse_risk_signal(value),
            trust: parse_numeric_signal(value, &["trust_score", "trust"], 1.0),
            grant,
            policy_fit: parse_policy_fit_signal(value),
            permission_fit: parse_permission_fit_signal(value, grant),
            runtime_health: parse_runtime_health_signal(value),
            cost_efficiency: parse_cost_efficiency_signal(value),
            latency: parse_latency_signal(value),
            success_rate: parse_success_rate_signal(value),
            freshness: parse_numeric_signal(value, &["freshness_score", "freshness"], 1.0),
            user_preference: parse_numeric_signal(
                value,
                &[
                    "user_preference_score",
                    "user_preference",
                    "personal_preference_score",
                    "personal_preference",
                ],
                1.0,
            ),
            organization_preference: parse_numeric_signal(
                value,
                &[
                    "organization_preference_score",
                    "organization_preference",
                    "org_preference_score",
                    "org_preference",
                ],
                1.0,
            ),
            ..Self::default()
        }
    }

    fn multiplier(&self) -> f64 {
        // Relevance remains dominant. Non-text signals gently reorder safe
        // candidates without letting popularity override a poor intent match.
        let weighted = (self.safety * 0.16)
            + (self.risk * 0.12)
            + (self.trust * 0.12)
            + (self.policy_fit * 0.12)
            + (self.permission_fit * 0.12)
            + (self.grant * 0.08)
            + (self.runtime_health * 0.08)
            + (self.success_rate * 0.07)
            + (self.cost_efficiency * 0.05)
            + (self.latency * 0.04)
            + (self.freshness * 0.02)
            + (self.user_preference * 0.01)
            + (self.organization_preference * 0.01)
            + (self.user_feedback.min(1.0) * 0.02);
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
    /// Candidate is denied by policy or license constraints.
    PolicyDenied,
    /// Unhealthy or disabled runtime.
    Unhealthy,
    /// Trust signal is below the safe threshold.
    Untrusted,
}

/// One deterministic offline ranking evaluation case.
///
/// The query is consumed only while evaluating the fixture. Reports reference
/// `id` instead of echoing query text so fixtures can model sensitive prompts
/// without leaking them through evaluation output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RankingEvalCase {
    /// Stable fixture identifier, for example `unsafe_exact_match`.
    pub id: String,
    /// Search query used by the fixture.
    pub query: String,
    /// Expected top tool after policy prefilters and adaptive ranking.
    pub expected_top_tool: String,
    /// Candidate JSON objects accepted by [`json_to_search_result`].
    pub candidates: Vec<Value>,
}

/// Per-case offline ranking result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RankingEvalCaseResult {
    /// Stable fixture identifier copied from [`RankingEvalCase::id`].
    pub id: String,
    /// Expected top tool for the fixture.
    pub expected_top_tool: String,
    /// Adaptive ranker top tool after policy prefilters.
    pub actual_top_tool: Option<String>,
    /// Text-only baseline top tool before adaptive signals and prefilters.
    pub baseline_top_tool: Option<String>,
    /// Whether the adaptive ranker selected the expected top tool.
    pub top1_hit: bool,
    /// Whether the text-only baseline selected the expected top tool.
    pub baseline_top1_hit: bool,
    /// Number of valid candidates removed by adaptive policy prefilters.
    pub filtered_candidates: usize,
    /// Number of malformed candidate objects ignored for this case.
    pub invalid_candidates: usize,
}

/// Measurable improvement target surfaced by offline ranking evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RankingImprovementTarget {
    /// Stable machine-readable target kind.
    pub kind: RankingImprovementTargetKind,
    /// Current measured value.
    pub current: f64,
    /// Target value for the next evaluation tranche.
    pub target: f64,
    /// Static explanation that does not include query or candidate payloads.
    pub reason: String,
}

/// Improvement target categories emitted by offline ranking evaluation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RankingImprovementTargetKind {
    /// Add more fixture cases before treating the suite as representative.
    ExpandFixtureCorpus,
    /// Improve top-1 quality for cases that miss the expected tool.
    ImproveTop1Quality,
    /// Add challenger cases where adaptive signals beat text-only ranking.
    AddChallengerCases,
    /// Add policy-filter cases for unsafe, unauthorized, unhealthy, or low-trust tools.
    AddPolicyPrefilterCases,
}

/// Aggregate offline ranking evaluation report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RankingEvalReport {
    /// Number of fixture cases evaluated.
    pub case_count: usize,
    /// Number of cases where adaptive ranking selected the expected tool.
    pub top1_hits: usize,
    /// Number of cases where the text-only baseline selected the expected tool.
    pub baseline_top1_hits: usize,
    /// Cases where adaptive ranking hit and the text-only baseline missed.
    pub improvements_over_baseline: usize,
    /// Cases where the text-only baseline hit and adaptive ranking missed.
    pub regressions_vs_baseline: usize,
    /// Total valid candidates suppressed by policy prefilters.
    pub filtered_candidates: usize,
    /// Total malformed candidate objects ignored.
    pub invalid_candidates: usize,
    /// Adaptive top-1 hit rate in `0.0..=1.0`.
    pub top1_hit_rate: f64,
    /// Text-only baseline top-1 hit rate in `0.0..=1.0`.
    pub baseline_top1_hit_rate: f64,
    /// Per-case results without query payloads.
    pub cases: Vec<RankingEvalCaseResult>,
    /// Measurable next improvement targets.
    pub improvement_targets: Vec<RankingImprovementTarget>,
}

/// Search ranker with usage-based weighting
pub struct SearchRanker {
    /// Usage counts per tool (key = "server:tool")
    usage_counts: DashMap<String, AtomicU64>,
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

fn build_eval_case_result(
    case: &RankingEvalCase,
    actual_top_tool: Option<String>,
    baseline_top_tool: Option<String>,
    filtered_candidates: usize,
    invalid_candidates: usize,
) -> RankingEvalCaseResult {
    let top1_hit = actual_top_tool.as_deref() == Some(case.expected_top_tool.as_str());
    let baseline_top1_hit = baseline_top_tool.as_deref() == Some(case.expected_top_tool.as_str());

    RankingEvalCaseResult {
        id: case.id.clone(),
        expected_top_tool: case.expected_top_tool.clone(),
        actual_top_tool,
        baseline_top_tool,
        top1_hit,
        baseline_top1_hit,
        filtered_candidates,
        invalid_candidates,
    }
}

fn baseline_top_tool(candidates: &[SearchResult], query: &str) -> Option<String> {
    let query_lower = query.to_lowercase();
    let words: Vec<&str> = query_lower.split_whitespace().collect();
    candidates
        .iter()
        .enumerate()
        .map(|(index, result)| {
            (
                index,
                result.tool.clone(),
                score_text_relevance(&result.tool, &result.description, &query_lower, &words),
            )
        })
        .max_by(|left, right| {
            left.2
                .partial_cmp(&right.2)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| right.0.cmp(&left.0))
        })
        .map(|(_, tool, _)| tool)
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
    if result.signals.risk < 0.75 {
        reasons.push("risk_downgraded".to_string());
    } else {
        reasons.push("risk_fit".to_string());
    }
    if result.signals.policy_fit < 0.75 {
        reasons.push("policy_downgraded".to_string());
    } else {
        reasons.push("policy_fit".to_string());
    }
    if result.signals.permission_fit < 0.75 {
        reasons.push("permission_downgraded".to_string());
    } else {
        reasons.push("permission_fit".to_string());
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
    if result.signals.success_rate < 0.75 {
        reasons.push("success_rate_downgraded".to_string());
    } else {
        reasons.push("success_rate_fit".to_string());
    }
    if result.signals.user_preference < 0.75 {
        reasons.push("user_preference_downgraded".to_string());
    } else {
        reasons.push("user_preference_fit".to_string());
    }
    if result.signals.organization_preference < 0.75 {
        reasons.push("organization_preference_downgraded".to_string());
    } else {
        reasons.push("organization_preference_fit".to_string());
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
    if signals.risk <= 0.0 {
        return Some(RankingExclusion {
            kind: RankingExclusionKind::Unsafe,
            reason: "suppressed_high_risk".to_string(),
        });
    }
    if signals.grant <= 0.0 {
        return Some(RankingExclusion {
            kind: RankingExclusionKind::Unauthorized,
            reason: "suppressed_unauthorized".to_string(),
        });
    }
    if signals.permission_fit <= 0.0 {
        return Some(RankingExclusion {
            kind: RankingExclusionKind::Unauthorized,
            reason: "suppressed_permission_denied".to_string(),
        });
    }
    if signals.policy_fit <= 0.0 {
        return Some(RankingExclusion {
            kind: RankingExclusionKind::PolicyDenied,
            reason: "suppressed_policy".to_string(),
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
    parse_optional_numeric_signal(value, keys).unwrap_or(default)
}

fn parse_optional_numeric_signal(value: &Value, keys: &[&str]) -> Option<f64> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_f64))
        .map(|score| score.clamp(0.0, 1.0))
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

fn parse_risk_signal(value: &Value) -> f64 {
    if let Some(level) = value
        .get("risk_level")
        .or_else(|| value.get("risk"))
        .and_then(Value::as_str)
    {
        return match level.to_ascii_lowercase().as_str() {
            "critical" | "high" | "unsafe" | "blocked" => 0.0,
            "medium" | "elevated" => 0.65,
            "low" => 0.9,
            _ => 1.0,
        };
    }
    if let Some(fit) =
        parse_optional_numeric_signal(value, &["risk_fit_score", "risk_fit", "risk_safety_score"])
    {
        return fit;
    }
    if let Some(score) = value.get("risk_score").and_then(Value::as_f64) {
        // `risk_score` is interpreted as risk severity, where higher means
        // riskier. `risk_fit` aliases above represent the inverse.
        return (1.0 - score).clamp(0.0, 1.0);
    }
    1.0
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

fn parse_permission_fit_signal(value: &Value, grant_default: f64) -> f64 {
    if value.get("authorized").and_then(Value::as_bool) == Some(false) {
        return 0.0;
    }
    if value
        .get("permission_status")
        .or_else(|| value.get("grant_status"))
        .or_else(|| value.get("permission"))
        .or_else(|| value.get("grant"))
        .and_then(Value::as_str)
        .is_some_and(|grant| matches!(grant, "denied" | "missing" | "unauthorized"))
    {
        return 0.0;
    }
    parse_optional_numeric_signal(
        value,
        &[
            "permission_fit_score",
            "permission_fit",
            "permission_score",
            "grant_score",
            "grant",
        ],
    )
    .unwrap_or(grant_default)
}

fn parse_policy_fit_signal(value: &Value) -> f64 {
    if value
        .get("policy_denied")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return 0.0;
    }
    if let Some(verdict) = value
        .get("policy_verdict")
        .or_else(|| value.get("policy_decision"))
        .or_else(|| value.get("policy"))
        .and_then(Value::as_str)
    {
        return match verdict.to_ascii_lowercase().as_str() {
            "deny" | "denied" | "block" | "blocked" | "quarantine" | "rejected" => 0.0,
            "warn" | "warning" | "advisory" | "review" => 0.65,
            _ => 1.0,
        };
    }
    parse_numeric_signal(
        value,
        &[
            "policy_fit_score",
            "policy_fit",
            "policy_score",
            "license_policy_fit",
        ],
        1.0,
    )
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

fn parse_success_rate_signal(value: &Value) -> f64 {
    if let Some(rate) = parse_optional_numeric_signal(
        value,
        &["success_rate", "success_score", "reliability_score"],
    ) {
        return rate;
    }
    if let Some(percent) = value.get("success_rate_percent").and_then(Value::as_f64) {
        return (percent / 100.0).clamp(0.0, 1.0);
    }
    let successes = value.get("success_count").and_then(Value::as_u64);
    let failures = value.get("failure_count").and_then(Value::as_u64);
    if let (Some(successes), Some(failures)) = (successes, failures) {
        let total = successes.saturating_add(failures);
        if total > 0 {
            #[allow(clippy::cast_precision_loss)]
            {
                return (successes as f64 / total as f64).clamp(0.0, 1.0);
            }
        }
    }
    1.0
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

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        {
            numerator as f64 / denominator as f64
        }
    }
}

fn improvement_targets_for(report: &RankingEvalReport) -> Vec<RankingImprovementTarget> {
    const MIN_FIXTURE_CASES: usize = 10;
    let mut targets = Vec::new();

    if report.case_count < MIN_FIXTURE_CASES {
        targets.push(RankingImprovementTarget {
            kind: RankingImprovementTargetKind::ExpandFixtureCorpus,
            current: count_as_metric(report.case_count),
            target: count_as_metric(MIN_FIXTURE_CASES),
            reason: "fixture_corpus_below_minimum".to_string(),
        });
    }
    if report.top1_hit_rate < 1.0 {
        targets.push(RankingImprovementTarget {
            kind: RankingImprovementTargetKind::ImproveTop1Quality,
            current: report.top1_hit_rate,
            target: 1.0,
            reason: "adaptive_top1_hit_rate_below_target".to_string(),
        });
    }
    if report.improvements_over_baseline == 0 {
        targets.push(RankingImprovementTarget {
            kind: RankingImprovementTargetKind::AddChallengerCases,
            current: 0.0,
            target: 1.0,
            reason: "no_fixture_demonstrates_adaptive_lift".to_string(),
        });
    }
    if report.filtered_candidates == 0 {
        targets.push(RankingImprovementTarget {
            kind: RankingImprovementTargetKind::AddPolicyPrefilterCases,
            current: 0.0,
            target: 1.0,
            reason: "no_fixture_exercises_policy_prefilters".to_string(),
        });
    }

    targets
}

fn count_as_metric(value: usize) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests;
