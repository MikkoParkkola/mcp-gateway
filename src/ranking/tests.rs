use super::*;

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

// ── score_text_relevance ─────────────────────────────────────────────

fn sr(tool: &str, description: &str) -> SearchResult {
    SearchResult::new("s", tool, description)
}

#[test]
fn score_text_relevance_exact_name_match_scores_10() {
    // GIVEN: single-word query exactly equals tool name
    // WHEN: scoring
    // THEN: score is 10
    let words = vec!["weather"];
    let score = score_text_relevance("weather", "Get weather data", "weather", &words);
    assert!((score - 10.0).abs() < f64::EPSILON);
}

#[test]
fn score_text_relevance_all_words_in_name_scores_15() {
    // GIVEN: multi-word query where ALL words are in tool name
    // WHEN: scoring
    // THEN: score is 15 (highest tier)
    let words = vec!["batch", "search"];
    let score = score_text_relevance("batch_search_tool", "Does stuff", "batch search", &words);
    assert!((score - 15.0).abs() < f64::EPSILON);
}

#[test]
fn score_text_relevance_all_words_in_combined_scores_by_word_count() {
    // GIVEN: "batch" in name, "research" only in description
    // WHEN: scoring with "batch research" (2 words)
    // THEN: score is 10 + 2*2 = 14 (all words found, scaled by count)
    let words = vec!["batch", "research"];
    let score = score_text_relevance(
        "batch_runner",
        "Executes deep research tasks",
        "batch research",
        &words,
    );
    assert!((score - 14.0).abs() < f64::EPSILON);
}

#[test]
fn score_text_relevance_keyword_exact_match_scores_8() {
    // GIVEN: description has [keywords: search, web, brave] and query word is "brave"
    // WHEN: scoring with single word "brave"
    // THEN: score is 8 (keyword exact match)
    let words = vec!["brave"];
    let score = score_text_relevance(
        "query_tool",
        "Query the web [keywords: search, web, brave]",
        "brave",
        &words,
    );
    assert!((score - 8.0).abs() < f64::EPSILON);
}

#[test]
fn score_text_relevance_partial_match_scores_by_matched_count() {
    // GIVEN: multi-word query "batch search", only "search" matches
    // WHEN: scoring
    // THEN: score is 3 + 2*1 = 5 (partial coverage, 1 word matched)
    let words = vec!["batch", "search"];
    let score = score_text_relevance("search_engine", "Search the web", "batch search", &words);
    assert!((score - 5.0).abs() < f64::EPSILON);
}

#[test]
fn score_text_relevance_full_query_in_name_scores_5() {
    // GIVEN: single-word query as substring of tool name (not exact)
    // WHEN: scoring
    // THEN: score is 5
    let words = vec!["search"];
    let score = score_text_relevance("search_engine", "Find things", "search", &words);
    assert!((score - 5.0).abs() < f64::EPSILON);
}

#[test]
fn score_text_relevance_full_query_in_description_scores_2() {
    // GIVEN: query only in description
    // WHEN: scoring
    // THEN: score is 2
    let words = vec!["forecast"];
    let score = score_text_relevance(
        "weather_api",
        "Get weather forecast data",
        "forecast",
        &words,
    );
    assert!((score - 2.0).abs() < f64::EPSILON);
}

#[test]
fn score_text_relevance_no_match_scores_0() {
    let words = vec!["unrelated"];
    let score = score_text_relevance(
        "weather_api",
        "Get current temperature",
        "unrelated",
        &words,
    );
    assert!((score - 0.0).abs() < f64::EPSILON);
}

#[test]
fn ranking_multi_word_query_all_words_in_name_beats_partial() {
    // GIVEN: "batch search" query, two results
    let search_ranker = SearchRanker::new();
    let results = vec![
        sr("search_only", "Does searching"), // only "search" in name -> score 7
        sr("batch_search_runner", "Multi-batch tool"), // both words in name -> score 15
    ];
    // WHEN: ranking
    let ranked = search_ranker.rank(results, "batch search");
    // THEN: full-name match wins
    assert_eq!(ranked[0].tool, "batch_search_runner");
}

#[test]
fn ranking_keyword_tag_scores_above_description_substring() {
    // GIVEN: "brave" query, one tool with keyword tag, one with desc substring
    let search_ranker = SearchRanker::new();
    let results = vec![
        sr("query_tool", "Use brave API to query stuff"), // desc contains -> 2
        sr("web_tool", "Web search [keywords: search, web, brave]"), // keyword match -> 8
    ];
    let ranked = search_ranker.rank(results, "brave");
    assert_eq!(ranked[0].tool, "web_tool");
    assert!(ranked[0].score > ranked[1].score);
}

#[test]
fn is_keyword_match_finds_exact_tag() {
    // GIVEN: description with [keywords: search, web, brave]
    let desc = "does stuff [keywords: search, web, brave]";
    // WHEN: checking each tag
    // THEN: all exact tags match, non-tags do not
    assert!(is_keyword_match(desc, "search"));
    assert!(is_keyword_match(desc, "web"));
    assert!(is_keyword_match(desc, "brave"));
    assert!(!is_keyword_match(desc, "stuff"));
    assert!(!is_keyword_match(desc, "does"));
}

#[test]
fn is_keyword_match_no_keywords_section_returns_false() {
    assert!(!is_keyword_match(
        "plain description with no tags",
        "search"
    ));
}

// ── expand_synonyms ──────────────────────────────────────────────────

#[test]
fn expand_synonyms_returns_group_for_known_word() {
    // GIVEN: "find" is in the search synonym group
    // WHEN: expanding
    // THEN: the full group is returned
    let syns = expand_synonyms("find");
    assert!(syns.contains(&"search"));
    assert!(syns.contains(&"find"));
    assert!(syns.contains(&"discover"));
    assert!(syns.contains(&"locate"));
}

#[test]
fn expand_synonyms_is_bidirectional() {
    // GIVEN: "search" and "find" are synonyms
    // WHEN: expanding both
    // THEN: each group contains the other word
    let from_search = expand_synonyms("search");
    let from_find = expand_synonyms("find");
    assert!(from_search.contains(&"find"));
    assert!(from_find.contains(&"search"));
}

#[test]
fn expand_synonyms_returns_empty_for_unknown_word() {
    assert!(expand_synonyms("xyzzy").is_empty());
    assert!(expand_synonyms("weather").is_empty());
}

#[test]
fn expand_synonyms_all_groups_are_bidirectional() {
    // Every word in a returned group should map back to the same group.
    let seeds = [
        "search", "monitor", "extract", "create", "analyze", "batch", "entity", "research", "send",
        "delete", "list", "convert", // new groups (T1.5)
        "execute", "show", "check", "modify", "count", "access", "store", "connect",
    ];
    for seed in seeds {
        let group = expand_synonyms(seed);
        assert!(!group.is_empty(), "seed '{seed}' has empty group");
        for member in group {
            let back = expand_synonyms(member);
            assert!(
                back.contains(&seed),
                "'{member}' does not map back to '{seed}'"
            );
        }
    }
}

// ── new synonym groups (T1.5) ─────────────────────────────────────────

#[test]
fn expand_synonyms_execute_group_contains_expected_members() {
    // GIVEN: "execute" is the canonical word for its group
    // WHEN: expanding
    // THEN: all alternate spellings are returned
    let group = expand_synonyms("execute");
    assert!(group.contains(&"run"));
    assert!(group.contains(&"invoke"));
    assert!(group.contains(&"call"));
    assert!(group.contains(&"trigger"));
}

#[test]
fn expand_synonyms_execute_group_is_bidirectional_via_alternates() {
    // GIVEN: "run", "invoke", "call", "trigger" are synonyms of "execute"
    // WHEN: expanding each alternate
    // THEN: each maps back to a group containing "execute"
    for word in &["run", "invoke", "call", "trigger"] {
        let group = expand_synonyms(word);
        assert!(
            group.contains(&"execute"),
            "'{word}' should map back to execute group"
        );
    }
}

#[test]
fn expand_synonyms_show_group_contains_expected_members() {
    // GIVEN: "show" is in the show group
    // WHEN: expanding any member
    // THEN: full group is present
    let group = expand_synonyms("display");
    assert!(group.contains(&"show"));
    assert!(group.contains(&"render"));
    assert!(group.contains(&"print"));
    assert!(group.contains(&"view"));
}

#[test]
fn expand_synonyms_check_group_contains_expected_members() {
    // GIVEN: "validate" is in the check group
    // WHEN: expanding
    // THEN: all members are returned
    let group = expand_synonyms("validate");
    assert!(group.contains(&"check"));
    assert!(group.contains(&"verify"));
    assert!(group.contains(&"test"));
    assert!(group.contains(&"assert"));
}

#[test]
fn expand_synonyms_modify_group_contains_expected_members() {
    // GIVEN: "update" is in the modify group
    // WHEN: expanding
    // THEN: all members are returned
    let group = expand_synonyms("update");
    assert!(group.contains(&"modify"));
    assert!(group.contains(&"edit"));
    assert!(group.contains(&"change"));
    assert!(group.contains(&"patch"));
}

#[test]
fn expand_synonyms_count_group_contains_expected_members() {
    // GIVEN: "aggregate" is in the count group
    // WHEN: expanding
    // THEN: all members are returned
    let group = expand_synonyms("aggregate");
    assert!(group.contains(&"count"));
    assert!(group.contains(&"summarize"));
    assert!(group.contains(&"total"));
    assert!(group.contains(&"tally"));
}

#[test]
fn expand_synonyms_access_group_contains_expected_members() {
    // GIVEN: "retrieve" is in the access group
    // WHEN: expanding
    // THEN: all members are returned
    let group = expand_synonyms("retrieve");
    assert!(group.contains(&"access"));
    assert!(group.contains(&"read"));
    assert!(group.contains(&"get"));
    assert!(group.contains(&"obtain"));
}

#[test]
fn expand_synonyms_store_group_contains_expected_members() {
    // GIVEN: "persist" is in the store group
    // WHEN: expanding
    // THEN: all members are returned
    let group = expand_synonyms("persist");
    assert!(group.contains(&"store"));
    assert!(group.contains(&"save"));
    assert!(group.contains(&"write"));
    assert!(group.contains(&"cache"));
}

#[test]
fn expand_synonyms_connect_group_contains_expected_members() {
    // GIVEN: "link" is in the connect group
    // WHEN: expanding
    // THEN: all members are returned
    let group = expand_synonyms("link");
    assert!(group.contains(&"connect"));
    assert!(group.contains(&"attach"));
    assert!(group.contains(&"join"));
    assert!(group.contains(&"bind"));
}

#[test]
fn expand_synonyms_total_group_count_is_at_least_twenty() {
    // GIVEN: all canonical group seeds
    // WHEN: counting distinct groups
    // THEN: at least 20 groups exist
    let all_seeds = [
        "search", "monitor", "extract", "create", "analyze", "batch", "entity", "research", "send",
        "delete", "list", "convert", "execute", "show", "check", "modify", "count", "access",
        "store", "connect",
    ];
    assert!(
        all_seeds.len() >= 20,
        "expected ≥20 synonym groups, got {}",
        all_seeds.len()
    );
    for seed in all_seeds {
        assert!(
            !expand_synonyms(seed).is_empty(),
            "group for '{seed}' is empty"
        );
    }
}

// ── synonym scoring ──────────────────────────────────────────────────

#[test]
fn score_text_relevance_synonym_name_match_scores_below_exact() {
    // GIVEN: query "find" and tool name "search_engine" (synonym of "find")
    // WHEN: scoring both an exact match and a synonym match
    // THEN: exact match scores higher
    let words_exact = vec!["search"];
    let words_syn = vec!["find"];
    let exact_score = score_text_relevance("search_engine", "Finds things", "search", &words_exact);
    let syn_score = score_text_relevance("search_engine", "Finds things", "find", &words_syn);
    // Both should be positive (synonym hit gives a score)
    assert!(syn_score > 0.0, "synonym should produce a positive score");
    // But exact beats synonym
    assert!(
        exact_score > syn_score,
        "exact ({exact_score}) should beat synonym ({syn_score})"
    );
}

#[test]
fn score_text_relevance_synonym_multiplier_is_applied() {
    // GIVEN: query "find" resolves via synonym to a name-contains match (score 5)
    // WHEN: scoring
    // THEN: score is 5 * 0.8 = 4.0
    let words = vec!["find"];
    let score = score_text_relevance("search_engine", "Retrieves data", "find", &words);
    let expected = 5.0 * SYNONYM_MULTIPLIER;
    assert!(
        (score - expected).abs() < 0.01,
        "expected {expected}, got {score}"
    );
}

#[test]
fn score_text_relevance_synonym_keyword_match_applies_discount() {
    // GIVEN: tool has [keywords: search] and query is "find" (synonym)
    // WHEN: scoring
    // THEN: 1-word keyword match = 8, discounted to 8 * 0.8 = 6.4
    let words = vec!["find"];
    let score = score_text_relevance("tool", "Does stuff [keywords: search, web]", "find", &words);
    let expected = 8.0 * SYNONYM_MULTIPLIER;
    assert!(
        (score - expected).abs() < 0.01,
        "expected {expected}, got {score}"
    );
}

#[test]
fn score_text_relevance_exact_keyword_beats_synonym_keyword() {
    // GIVEN: tool has [keywords: search] and two queries: "search" (exact) and "find" (synonym)
    let words_exact = vec!["search"];
    let words_syn = vec!["find"];
    let desc = "Does stuff [keywords: search, web]";
    let exact = score_text_relevance("tool", desc, "search", &words_exact);
    let syn = score_text_relevance("tool", desc, "find", &words_syn);
    assert!(exact > syn, "exact ({exact}) should beat synonym ({syn})");
}

#[test]
fn ranking_synonym_query_finds_matching_tools() {
    // GIVEN: query "find companies" where "find" is a synonym for "search"
    // WHEN: ranking against a tool with "search" in its name
    let search_ranker = SearchRanker::new();
    let results = vec![
        sr(
            "company_search",
            "Search for companies [keywords: search, company]",
        ),
        sr("weather_api", "Get current temperature"),
    ];
    let ranked = search_ranker.rank(results, "find companies");
    // THEN: the search tool should score above 0 due to synonym expansion
    assert!(
        ranked
            .iter()
            .find(|r| r.tool == "company_search")
            .unwrap()
            .score
            > 0.0,
        "synonym-expanded query should match"
    );
    assert_eq!(ranked[0].tool, "company_search");
}

#[test]
fn ranking_exact_match_beats_synonym_match() {
    // GIVEN: one tool has exact word "search", another only matches via "find" synonym
    let search_ranker = SearchRanker::new();
    let results = vec![
        sr("find_companies", "Discovers companies"), // exact "find" in name
        sr("search_companies", "Searches companies"), // synonym of "find"
    ];
    let ranked = search_ranker.rank(results, "find");
    // The tool with exact "find" in its name should score at least as high
    assert!(
        ranked[0].score >= ranked[1].score,
        "exact match should score >= synonym match"
    );
}

#[test]
fn is_keyword_match_with_synonyms_finds_synonym_tag() {
    // GIVEN: description has [keywords: search] and we check "find" (synonym)
    let desc = "does stuff [keywords: search, web]";
    assert!(
        is_keyword_match_with_synonyms(desc, "find"),
        "'find' should match via synonym 'search'"
    );
}

#[test]
fn is_keyword_match_with_synonyms_still_finds_exact() {
    let desc = "does stuff [keywords: search, web]";
    assert!(is_keyword_match_with_synonyms(desc, "search"));
}

#[test]
fn is_keyword_match_with_synonyms_returns_false_for_no_match() {
    let desc = "does stuff [keywords: weather, temperature]";
    assert!(!is_keyword_match_with_synonyms(desc, "find"));
}
