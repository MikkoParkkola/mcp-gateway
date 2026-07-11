// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Cost-optimization suggestions.
//!
//! When a tool in a known equivalence category is invoked and a cheaper
//! alternative is available, `suggest_cheaper()` returns a [`CostSuggestion`]
//! that the invoke path injects as `_cost_suggestion` in the response.
//!
//! # Category sources (priority order)
//!
//! 1. `cost_governance.alternatives` in `config.yaml` (user-configured) — fully
//!    replaces the compiled-in defaults when present.
//! 2. `DEFAULT_CATEGORY_EQUIVALENCES` — compiled-in defaults covering the
//!    most common AI agent tool categories.

use std::collections::HashMap;

/// A cost-optimization suggestion to inject into the tool response.
#[cfg(feature = "cost-governance")]
#[derive(Debug, Clone, serde::Serialize)]
pub struct CostSuggestion {
    /// Tool that was invoked.
    pub tool: String,
    /// Per-call cost of the invoked tool (USD).
    pub cost: f64,
    /// Name of the cheaper alternative tool.
    pub alternative: String,
    /// Per-call cost of the alternative (USD).
    pub alternative_cost: f64,
    /// Savings per call (USD).
    pub savings_per_call: f64,
    /// Human-readable explanation.
    pub reason: String,
}

/// Compiled-in default category equivalences.
///
/// Overridden entirely by `cost_governance.alternatives` when configured.
const DEFAULT_CATEGORY_EQUIVALENCES: &[(&str, &[&str])] = &[
    (
        "web_search",
        &["tavily_search", "brave_search", "exa_search"],
    ),
    ("deep_research", &["exa_deep_research", "tavily_research"]),
    ("code_search", &["exa_code_search", "brave_search"]),
];

/// Generate a cost-optimization suggestion for `tool_name`.
///
/// Returns `None` when:
/// - The tool is not in any known equivalence category.
/// - No cheaper alternative is registered in `all_costs`.
/// - The tool is already the cheapest in its category.
///
/// `configured_alternatives` overrides `DEFAULT_CATEGORY_EQUIVALENCES`
/// entirely when `Some`.
#[cfg(feature = "cost-governance")]
#[must_use]
#[allow(clippy::implicit_hasher)]
pub fn suggest_cheaper(
    tool_name: &str,
    tool_cost: f64,
    all_costs: &HashMap<String, f64>,
    configured_alternatives: Option<&HashMap<String, Vec<String>>>,
) -> Option<CostSuggestion> {
    if let Some(alternatives) = configured_alternatives {
        // Use config-provided categories
        for (category, members) in alternatives {
            if !members.iter().any(|m| m == tool_name) {
                continue;
            }
            if let Some((alt_name, alt_cost)) = find_cheapest_alternative(
                tool_name,
                tool_cost,
                members.iter().map(String::as_str),
                all_costs,
            ) {
                return Some(build_suggestion(
                    tool_name, tool_cost, alt_name, alt_cost, category,
                ));
            }
        }
        return None;
    }

    // Fallback: compiled-in defaults
    for &(category, members) in DEFAULT_CATEGORY_EQUIVALENCES {
        if !members.contains(&tool_name) {
            continue;
        }
        if let Some((alt_name, alt_cost)) =
            find_cheapest_alternative(tool_name, tool_cost, members.iter().copied(), all_costs)
        {
            return Some(build_suggestion(
                tool_name, tool_cost, alt_name, alt_cost, category,
            ));
        }
    }

    None
}

/// Find the cheapest alternative to `tool_name` in `category_members`.
///
/// Returns `(alt_name, alt_cost)` only when `alt_cost < tool_cost`.
fn find_cheapest_alternative<'a>(
    tool_name: &str,
    tool_cost: f64,
    category_members: impl Iterator<Item = &'a str>,
    all_costs: &HashMap<String, f64>,
) -> Option<(&'a str, f64)> {
    let mut cheapest: Option<(&str, f64)> = None;
    for member in category_members {
        if member == tool_name {
            continue;
        }
        let Some(&cost) = all_costs.get(member) else {
            continue;
        };
        if cost >= tool_cost {
            continue;
        }
        match cheapest {
            None => cheapest = Some((member, cost)),
            Some((_, c)) if cost < c => cheapest = Some((member, cost)),
            _ => {}
        }
    }
    cheapest
}

fn build_suggestion(
    tool_name: &str,
    tool_cost: f64,
    alt_name: &str,
    alt_cost: f64,
    category: &str,
) -> CostSuggestion {
    let savings = tool_cost - alt_cost;
    CostSuggestion {
        tool: tool_name.to_string(),
        cost: tool_cost,
        alternative: alt_name.to_string(),
        alternative_cost: alt_cost,
        savings_per_call: savings,
        reason: format!("Both in '{category}' category. {alt_name} saves ${savings:.4}/call"),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn costs(pairs: &[(&str, f64)]) -> HashMap<String, f64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn suggest_cheaper_returns_alternative_for_expensive_tool() {
        // tavily ($0.01) vs brave ($0.005) — brave is cheaper
        let all = costs(&[("tavily_search", 0.01), ("brave_search", 0.005)]);
        let suggestion = suggest_cheaper("tavily_search", 0.01, &all, None).unwrap();
        assert_eq!(suggestion.tool, "tavily_search");
        assert_eq!(suggestion.alternative, "brave_search");
        assert!((suggestion.savings_per_call - 0.005).abs() < 1e-9);
    }

    #[test]
    fn suggest_no_alternative_for_unique_tool() {
        // unique_tool is not in any category
        let all = costs(&[("unique_tool", 0.01)]);
        let suggestion = suggest_cheaper("unique_tool", 0.01, &all, None);
        assert!(suggestion.is_none());
    }

    #[test]
    fn suggest_returns_none_when_already_cheapest() {
        // brave ($0.005) is cheapest in web_search — no cheaper alternative
        let all = costs(&[
            ("tavily_search", 0.01),
            ("brave_search", 0.005),
            ("exa_search", 0.005),
        ]);
        let suggestion = suggest_cheaper("brave_search", 0.005, &all, None);
        assert!(suggestion.is_none());
    }

    #[test]
    fn suggest_uses_configured_alternatives_over_defaults() {
        // Custom category overrides defaults
        let mut configured: HashMap<String, Vec<String>> = HashMap::new();
        configured.insert(
            "my_category".to_string(),
            vec!["tool_a".to_string(), "tool_b".to_string()],
        );
        let all = costs(&[("tool_a", 0.05), ("tool_b", 0.01)]);
        let suggestion = suggest_cheaper("tool_a", 0.05, &all, Some(&configured)).unwrap();
        assert_eq!(suggestion.alternative, "tool_b");
        assert!((suggestion.savings_per_call - 0.04).abs() < 1e-9);
    }

    #[test]
    fn suggest_configured_alternatives_returns_none_for_unknown_tool() {
        let mut configured: HashMap<String, Vec<String>> = HashMap::new();
        configured.insert(
            "cat".to_string(),
            vec!["tool_a".to_string(), "tool_b".to_string()],
        );
        let all = costs(&[("tool_a", 0.05), ("tool_b", 0.01)]);
        // "tool_c" is not in configured alternatives
        let suggestion = suggest_cheaper("tool_c", 0.05, &all, Some(&configured));
        assert!(suggestion.is_none());
    }

    #[test]
    fn suggest_picks_cheapest_when_multiple_alternatives() {
        // exa ($0.008) is cheaper than tavily ($0.01), brave ($0.005) is cheapest
        let all = costs(&[
            ("tavily_search", 0.01),
            ("exa_search", 0.008),
            ("brave_search", 0.005),
        ]);
        let suggestion = suggest_cheaper("tavily_search", 0.01, &all, None).unwrap();
        assert_eq!(suggestion.alternative, "brave_search");
    }
}
