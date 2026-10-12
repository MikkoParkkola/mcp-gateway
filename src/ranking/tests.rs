// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

mod backend_name;
mod relevance;
mod schema;

#[test]
fn test_record_and_retrieve_usage() {
    let ranker = SearchRanker::new();
    ranker.record_use("server1", "tool1");
    ranker.record_use("server1", "tool1");
    ranker.record_use("server2", "tool2");

    assert_eq!(ranker.usage_count("server1", "tool1"), 2);
    assert_eq!(ranker.usage_count("server2", "tool2"), 1);
    assert_eq!(ranker.usage_count("server3", "tool3"), 0);
}

#[test]
fn test_ranking_with_text_relevance() {
    let search_ranker = SearchRanker::new();
    let results = vec![
        SearchResult {
            server: "s1".to_string(),
            tool: "weather".to_string(), // Exact match
            description: "Get weather".to_string(),
            ..SearchResult::new("s1", "weather", "Get weather")
        },
        SearchResult {
            server: "s2".to_string(),
            tool: "get_weather_forecast".to_string(), // Contains
            description: "Forecast".to_string(),
            ..SearchResult::new("s2", "get_weather_forecast", "Forecast")
        },
        SearchResult {
            server: "s3".to_string(),
            tool: "forecast".to_string(),
            description: "Get weather data".to_string(), // Desc contains
            ..SearchResult::new("s3", "forecast", "Get weather data")
        },
    ];

    let ranked = search_ranker.rank(results, "weather");

    assert_eq!(ranked[0].tool, "weather"); // Exact match first
    assert_eq!(ranked[1].tool, "get_weather_forecast"); // Contains second
    assert_eq!(ranked[2].tool, "forecast"); // Desc contains last
}

#[test]
fn test_ranking_with_usage_boost() {
    let usage_ranker = SearchRanker::new();

    // Popular tool
    for _ in 0..100 {
        usage_ranker.record_use("s1", "popular");
    }

    let results = vec![
        SearchResult {
            server: "s1".to_string(),
            tool: "popular".to_string(),
            description: "Contains search term".to_string(),
            ..SearchResult::new("s1", "popular", "Contains search term")
        },
        SearchResult {
            server: "s2".to_string(),
            tool: "exact".to_string(), // Exact match but no usage
            description: "Something".to_string(),
            ..SearchResult::new("s2", "exact", "Something")
        },
    ];

    let ranked = usage_ranker.rank(results, "search");

    // "popular" has desc match (2 pts) × (1 + log2(101)*0.15) ≈ 2 × 2.0 = 4.0
    // "exact" has no match (0 points, usage irrelevant with multiplicative)
    assert_eq!(ranked[0].tool, "popular");
}

#[test]
fn test_save_and_load() {
    let ranker = SearchRanker::new();
    ranker.record_use("s1", "t1");
    ranker.record_use("s1", "t1");
    ranker.record_use("s2", "t2");

    let temp = std::env::temp_dir().join("test_ranking.json");

    ranker.save(&temp).unwrap();

    let new_ranker = SearchRanker::new();
    new_ranker.load(&temp).unwrap();

    assert_eq!(new_ranker.usage_count("s1", "t1"), 2);
    assert_eq!(new_ranker.usage_count("s2", "t2"), 1);

    std::fs::remove_file(temp).ok();
}

#[test]
fn persisted_usage_feedback_omits_query_and_argument_payloads() {
    let ranker = SearchRanker::new();
    ranker.record_use("search_backend", "company_lookup");

    let temp = std::env::temp_dir().join(format!(
        "test_ranking_feedback_privacy_{}.json",
        std::process::id()
    ));
    ranker.save(&temp).unwrap();

    let content = std::fs::read_to_string(&temp).unwrap();
    let entries: Vec<serde_json::Value> = serde_json::from_str(&content).unwrap();
    let mut keys: Vec<_> = entries[0].as_object().unwrap().keys().cloned().collect();
    keys.sort();

    assert_eq!(entries.len(), 1);
    assert_eq!(
        keys,
        vec![
            "count".to_string(),
            "server".to_string(),
            "tool".to_string()
        ]
    );
    assert!(!content.contains("query"));
    assert!(!content.contains("arguments"));
    assert!(!content.contains("payload"));
    assert!(!content.contains("ACME-12345"));

    std::fs::remove_file(temp).ok();
}

#[test]
fn test_default_impl() {
    let ranker = SearchRanker::default();
    assert_eq!(ranker.usage_count("s1", "t1"), 0);
}

#[test]
fn test_clear() {
    let ranker = SearchRanker::new();
    ranker.record_use("s1", "t1");
    ranker.record_use("s2", "t2");

    ranker.clear();

    assert_eq!(ranker.usage_count("s1", "t1"), 0);
    assert_eq!(ranker.usage_count("s2", "t2"), 0);
}

#[test]
fn test_json_to_search_result() {
    let value = serde_json::json!({
        "server": "test-server",
        "tool": "test-tool",
        "description": "Test description",
        "policy_verdict": "allow",
        "permission_fit": 0.9,
        "success_rate": 0.98,
        "user_preference": 0.85,
        "org_preference": 0.8
    });

    let result = json_to_search_result(&value).unwrap();
    assert_eq!(result.server, "test-server");
    assert_eq!(result.tool, "test-tool");
    assert_eq!(result.description, "Test description");
    assert!(result.score < f64::EPSILON);
    assert!((result.signals.policy_fit - 1.0).abs() < f64::EPSILON);
    assert!((result.signals.permission_fit - 0.9).abs() < f64::EPSILON);
    assert!((result.signals.success_rate - 0.98).abs() < f64::EPSILON);
    assert!((result.signals.user_preference - 0.85).abs() < f64::EPSILON);
    assert!((result.signals.organization_preference - 0.8).abs() < f64::EPSILON);
}

#[test]
fn test_json_to_search_result_missing_fields() {
    let value = serde_json::json!({
        "server": "test-server"
    });

    let result = json_to_search_result(&value);
    assert!(result.is_none());
}

#[test]
fn test_ranking_empty_results() {
    let search_ranker = SearchRanker::new();
    let results = vec![];

    let ranked = search_ranker.rank(results, "test");
    assert_eq!(ranked.len(), 0);
}

#[test]
fn test_ranking_preserves_unmatched() {
    let search_ranker = SearchRanker::new();
    let results = vec![
        SearchResult {
            server: "s1".to_string(),
            tool: "unrelated".to_string(),
            description: "No match".to_string(),
            ..SearchResult::new("s1", "unrelated", "No match")
        },
        SearchResult {
            server: "s2".to_string(),
            tool: "also_unrelated".to_string(),
            description: "Still no match".to_string(),
            ..SearchResult::new("s2", "also_unrelated", "Still no match")
        },
    ];

    let ranked = search_ranker.rank(results, "test");
    assert_eq!(ranked.len(), 2);
    // Both should have score 0.0 (no text match, no usage)
    assert!(ranked[0].score < f64::EPSILON);
    assert!(ranked[1].score < f64::EPSILON);
}

#[test]
fn ranking_suppresses_unsafe_unauthorized_unhealthy_and_untrusted_tools() {
    let search_ranker = SearchRanker::new();
    let candidates = vec![
        json_to_search_result(&serde_json::json!({
            "server": "s",
            "tool": "unsafe_search",
            "description": "Search everything",
            "unsafe": true
        }))
        .unwrap(),
        json_to_search_result(&serde_json::json!({
            "server": "s",
            "tool": "unauthorized_search",
            "description": "Search everything",
            "authorized": false
        }))
        .unwrap(),
        json_to_search_result(&serde_json::json!({
            "server": "s",
            "tool": "unhealthy_search",
            "description": "Search everything",
            "status": "disabled"
        }))
        .unwrap(),
        json_to_search_result(&serde_json::json!({
            "server": "s",
            "tool": "untrusted_search",
            "description": "Search everything",
            "trust_score": 0.1
        }))
        .unwrap(),
        json_to_search_result(&serde_json::json!({
            "server": "s",
            "tool": "safe_search",
            "description": "Search everything",
            "trust_score": 0.9,
            "authorized": true
        }))
        .unwrap(),
    ];

    let ranked = search_ranker.rank(candidates, "search");

    assert_eq!(ranked.len(), 1);
    assert_eq!(ranked[0].tool, "safe_search");
    assert!(ranked[0].explanation.included);
}

#[test]
fn ranking_suppresses_policy_denied_and_high_risk_tools() {
    let search_ranker = SearchRanker::new();
    let candidates = vec![
        json_to_search_result(&serde_json::json!({
            "server": "s",
            "tool": "policy_blocked_search",
            "description": "Search everything",
            "policy_verdict": "block"
        }))
        .unwrap(),
        json_to_search_result(&serde_json::json!({
            "server": "s",
            "tool": "risk_blocked_search",
            "description": "Search everything",
            "risk_score": 1.0
        }))
        .unwrap(),
        json_to_search_result(&serde_json::json!({
            "server": "s",
            "tool": "safe_policy_search",
            "description": "Search everything",
            "policy_verdict": "allow",
            "risk_level": "low"
        }))
        .unwrap(),
    ];

    let ranked = search_ranker.rank(candidates, "search");

    assert_eq!(ranked.len(), 1);
    assert_eq!(ranked[0].tool, "safe_policy_search");
    assert!(ranked[0].explanation.included);
}

#[test]
fn ranking_uses_cost_latency_trust_and_feedback_as_safe_downgrades() {
    let search_ranker = SearchRanker::new();
    search_ranker.record_use("s", "cheap_fast_search");
    let candidates = vec![
        json_to_search_result(&serde_json::json!({
            "server": "s",
            "tool": "expensive_slow_search",
            "description": "Search documents",
            "cost_category": "high",
            "latency_ms": 2500,
            "trust_score": 0.6,
            "authorized": true
        }))
        .unwrap(),
        json_to_search_result(&serde_json::json!({
            "server": "s",
            "tool": "cheap_fast_search",
            "description": "Search documents",
            "cost_category": "free",
            "latency_ms": 50,
            "trust_score": 0.95,
            "authorized": true
        }))
        .unwrap(),
    ];

    let ranked = search_ranker.rank(candidates, "search documents");

    assert_eq!(ranked[0].tool, "cheap_fast_search");
    assert!(ranked[0].signals.user_feedback > 0.0);
    assert!(
        ranked[1]
            .explanation
            .reasons
            .contains(&"cost_downgraded".to_string())
    );
    assert!(
        ranked[1]
            .explanation
            .reasons
            .contains(&"latency_downgraded".to_string())
    );
    assert!(
        ranked[1]
            .explanation
            .reasons
            .contains(&"trust_downgraded".to_string())
    );
}

#[test]
fn ranking_uses_policy_permission_success_and_preferences_as_explainable_signals() {
    let search_ranker = SearchRanker::new();
    let candidates = vec![
        json_to_search_result(&serde_json::json!({
            "server": "s",
            "tool": "preferred_search",
            "description": "Search documents",
            "policy_fit": 1.0,
            "permission_fit": 1.0,
            "success_rate": 0.99,
            "user_preference": 1.0,
            "organization_preference": 1.0
        }))
        .unwrap(),
        json_to_search_result(&serde_json::json!({
            "server": "s",
            "tool": "downgraded_search",
            "description": "Search documents",
            "policy_fit": 0.65,
            "permission_fit": 0.6,
            "success_rate": 0.5,
            "user_preference": 0.5,
            "organization_preference": 0.4
        }))
        .unwrap(),
    ];

    let ranked = search_ranker.rank(candidates, "search documents");

    assert_eq!(ranked[0].tool, "preferred_search");
    let downgraded = ranked
        .iter()
        .find(|result| result.tool == "downgraded_search")
        .unwrap();
    assert!(
        downgraded
            .explanation
            .reasons
            .contains(&"policy_downgraded".to_string())
    );
    assert!(
        downgraded
            .explanation
            .reasons
            .contains(&"permission_downgraded".to_string())
    );
    assert!(
        downgraded
            .explanation
            .reasons
            .contains(&"success_rate_downgraded".to_string())
    );
    assert!(
        downgraded
            .explanation
            .reasons
            .contains(&"user_preference_downgraded".to_string())
    );
    assert!(
        downgraded
            .explanation
            .reasons
            .contains(&"organization_preference_downgraded".to_string())
    );
}

#[test]
fn ranking_explanation_does_not_echo_query_payload() {
    let search_ranker = SearchRanker::new();
    let candidates = vec![
        json_to_search_result(&serde_json::json!({
            "server": "s",
            "tool": "invoice_search",
            "description": "Search invoices",
            "authorized": true
        }))
        .unwrap(),
    ];

    let ranked = search_ranker.rank(candidates, "search invoice ACME-12345");
    let explanation = serde_json::to_string(&ranked[0].explanation).unwrap();

    assert!(ranked[0].explanation.included);
    assert!(!explanation.contains("ACME-12345"));
    assert!(ranked[0].signals.relevance > 0.0);
}

fn offline_eval_cases(query: &str) -> Vec<RankingEvalCase> {
    vec![
        RankingEvalCase {
            id: "unsafe_exact_match".to_string(),
            query: "delete file".to_string(),
            expected_top_tool: "safe_delete".to_string(),
            candidates: vec![
                serde_json::json!({
                    "server": "s",
                    "tool": "delete_file",
                    "description": "Delete file without confirmation",
                    "risk_level": "critical"
                }),
                serde_json::json!({
                    "server": "s",
                    "tool": "safe_delete",
                    "description": "Delete files after confirmation [keywords: delete, file]",
                    "authorized": true,
                    "trust_score": 0.95
                }),
            ],
        },
        RankingEvalCase {
            id: "weather_literal".to_string(),
            query: "weather forecast".to_string(),
            expected_top_tool: "weather_forecast".to_string(),
            candidates: vec![
                serde_json::json!({
                    "server": "s",
                    "tool": "weather_forecast",
                    "description": "Get weather forecast"
                }),
                serde_json::json!({
                    "server": "s",
                    "tool": "weather_history",
                    "description": "Get historical weather"
                }),
            ],
        },
        RankingEvalCase {
            id: "company_discovery".to_string(),
            query: query.to_string(),
            expected_top_tool: "company_search".to_string(),
            candidates: vec![
                serde_json::json!({
                    "server": "s",
                    "tool": "company_search",
                    "description": "Find companies and organizations [keywords: search, companies]"
                }),
                serde_json::json!({
                    "server": "s",
                    "tool": "person_search",
                    "description": "Find people and saved contacts"
                }),
            ],
        },
    ]
}

#[test]
fn offline_evaluation_compares_baseline_and_reports_targets() {
    let search_ranker = SearchRanker::new();
    let report = search_ranker.evaluate_offline(&offline_eval_cases("find companies"));

    assert_eq!(report.case_count, 3);
    assert_eq!(report.top1_hits, 3);
    assert_eq!(report.baseline_top1_hits, 2);
    assert_eq!(report.improvements_over_baseline, 1);
    assert_eq!(report.regressions_vs_baseline, 0);
    assert_eq!(report.filtered_candidates, 1);
    assert!(report.top1_hit_rate > report.baseline_top1_hit_rate);
    assert!(report.improvement_targets.iter().any(|target| {
        target.kind == RankingImprovementTargetKind::ExpandFixtureCorpus
            && (target.current - 3.0).abs() < f64::EPSILON
            && (target.target - 10.0).abs() < f64::EPSILON
    }));

    let unsafe_case = report
        .cases
        .iter()
        .find(|case| case.id == "unsafe_exact_match")
        .unwrap();
    assert_eq!(
        unsafe_case.baseline_top_tool.as_deref(),
        Some("delete_file")
    );
    assert_eq!(unsafe_case.actual_top_tool.as_deref(), Some("safe_delete"));
    assert!(unsafe_case.top1_hit);
    assert!(!unsafe_case.baseline_top1_hit);
}

#[test]
fn offline_evaluation_report_does_not_echo_query_payload() {
    let search_ranker = SearchRanker::new();
    let report = search_ranker.evaluate_offline(&offline_eval_cases("find companies ACME-12345"));
    let report_json = serde_json::to_string(&report).unwrap();

    assert!(!report_json.contains("ACME-12345"));
    assert!(!report_json.contains("find companies"));
    assert!(report_json.contains("company_discovery"));
}

fn sr(tool: &str, description: &str) -> SearchResult {
    SearchResult::new("s", tool, description)
}
