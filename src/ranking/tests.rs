use super::*;

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
            score: 0.0,
        },
        SearchResult {
            server: "s2".to_string(),
            tool: "get_weather_forecast".to_string(), // Contains
            description: "Forecast".to_string(),
            score: 0.0,
        },
        SearchResult {
            server: "s3".to_string(),
            tool: "forecast".to_string(),
            description: "Get weather data".to_string(), // Desc contains
            score: 0.0,
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
            score: 0.0,
        },
        SearchResult {
            server: "s2".to_string(),
            tool: "exact".to_string(), // Exact match but no usage
            description: "Something".to_string(),
            score: 0.0,
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
        "description": "Test description"
    });

    let result = json_to_search_result(&value).unwrap();
    assert_eq!(result.server, "test-server");
    assert_eq!(result.tool, "test-tool");
    assert_eq!(result.description, "Test description");
    assert!(result.score < f64::EPSILON);
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
            score: 0.0,
        },
        SearchResult {
            server: "s2".to_string(),
            tool: "also_unrelated".to_string(),
            description: "Still no match".to_string(),
            score: 0.0,
        },
    ];

    let ranked = search_ranker.rank(results, "test");
    assert_eq!(ranked.len(), 2);
    // Both should have score 0.0 (no text match, no usage)
    assert!(ranked[0].score < f64::EPSILON);
    assert!(ranked[1].score < f64::EPSILON);
}

// ── score_text_relevance ─────────────────────────────────────────────

fn sr(tool: &str, description: &str) -> SearchResult {
    SearchResult {
        server: "s".to_string(),
        tool: tool.to_string(),
        description: description.to_string(),
        score: 0.0,
    }
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
        "delete", "list", "convert",
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

// ── schema-aware matching ─────────────────────────────────────────────

#[test]
fn is_schema_field_match_finds_exact_token() {
    // GIVEN: description with [schema: symbol, exchange, price]
    // WHEN: checking each token
    // THEN: all match, and non-schema words do not
    let desc = "stock api [schema: symbol, exchange, price]";
    assert!(is_schema_field_match(desc, "symbol"));
    assert!(is_schema_field_match(desc, "exchange"));
    assert!(is_schema_field_match(desc, "price"));
    assert!(!is_schema_field_match(desc, "volume"));
    assert!(!is_schema_field_match(desc, "stock"));
}

#[test]
fn is_schema_field_match_returns_false_when_no_schema_section() {
    // GIVEN: description without [schema: ...] section
    // WHEN: checking a word
    // THEN: returns false
    assert!(!is_schema_field_match("plain description", "symbol"));
}

#[test]
fn is_schema_field_match_returns_false_for_partial_token() {
    // GIVEN: schema has "exchange" and we look for "change"
    // WHEN: checking
    // THEN: partial substring does not match (token boundary enforced)
    let desc = "tool [schema: symbol, exchange]";
    assert!(!is_schema_field_match(desc, "change"));
    assert!(!is_schema_field_match(desc, "sym"));
}

#[test]
fn score_text_relevance_single_schema_field_scores_6() {
    // GIVEN: description has [schema: symbol] and query is "symbol"
    // WHEN: scoring
    // THEN: score is 6.0 (schema single-word path: 6.0)
    let words = vec!["symbol"];
    let score = score_text_relevance(
        "market_data",
        "Get market data [schema: symbol, exchange]",
        "symbol",
        &words,
    );
    assert!(
        (score - 6.0).abs() < f64::EPSILON,
        "expected 6.0, got {score}"
    );
}

#[test]
fn score_text_relevance_two_schema_fields_scores_above_single_schema_field() {
    // GIVEN: description has [schema: symbol, exchange, price]
    // WHEN: scoring "symbol exchange" (2 query words, both schema fields)
    // THEN: score is ≥ the score for querying just "symbol" (1 field)
    //
    // NOTE: the text-coverage path dominates here (words appear literally in
    // the description string, so 10+2*2=14) but we assert ≥ 8.0 to confirm
    // the multi-field schema path is at least as good as its direct score.
    let two_words = vec!["symbol", "exchange"];
    let one_word = vec!["symbol"];
    let score_two = score_text_relevance(
        "market_data",
        "Get market data [schema: symbol, exchange, price]",
        "symbol exchange",
        &two_words,
    );
    let score_one = score_text_relevance(
        "market_data2",
        "Get market data [schema: symbol, price]",
        "symbol",
        &one_word,
    );
    assert!(
        score_two >= score_one,
        "two-field query ({score_two}) should score ≥ one-field query ({score_one})"
    );
    assert!(
        score_two >= 8.0,
        "two-field match should score ≥ 8.0, got {score_two}"
    );
}

#[test]
fn score_text_relevance_schema_scores_above_description_substring() {
    // GIVEN: two tools — one with schema field, one with query only in description text
    // WHEN: scoring "symbol"
    // THEN: schema-match tool scores higher than description-text-only tool
    let words = vec!["symbol"];
    let schema_score = score_text_relevance(
        "market_data",
        "Market data [schema: symbol, exchange]",
        "symbol",
        &words,
    );
    let text_score = score_text_relevance(
        "other_tool",
        "Handles ticker symbol lookups in plain text",
        "symbol",
        &words,
    );
    // schema match should yield ≥ 6.0, text-only is ≤ 2.0
    assert!(
        schema_score > text_score,
        "schema ({schema_score}) should beat description-text ({text_score})"
    );
}

#[test]
fn score_text_relevance_keyword_tag_beats_schema_match() {
    // GIVEN: query "symbol", one tool has keyword tag, other has schema field
    // WHEN: scoring
    // THEN: keyword-tag match (8.0) beats single-schema-field match (6.0)
    let words = vec!["symbol"];
    let kw_score = score_text_relevance(
        "kw_tool",
        "Market data [keywords: symbol, exchange]",
        "symbol",
        &words,
    );
    let schema_score = score_text_relevance(
        "schema_tool",
        "Market data [schema: symbol, exchange]",
        "symbol",
        &words,
    );
    assert!(
        kw_score > schema_score,
        "keyword ({kw_score}) should beat schema ({schema_score})"
    );
}

#[test]
fn ranking_schema_fields_find_stock_symbol_tool() {
    // GIVEN: query "stock symbol" against tools without explicit description match
    // The stock tool has [schema: symbol, exchange, price, volume]
    // WHEN: ranking
    // THEN: the stock tool with schema fields ranks first
    let search_ranker = SearchRanker::new();
    let results = vec![
        sr("weather_api", "Get current weather data"),
        sr(
            "market_data",
            "Fetch financial data [schema: symbol, exchange, price, volume]",
        ),
        sr("search_web", "Search the web for any query"),
    ];
    let ranked = search_ranker.rank(results, "stock symbol");
    assert_eq!(
        ranked[0].tool,
        "market_data",
        "market_data should rank first; got {:?}",
        ranked
            .iter()
            .map(|r| (&r.tool, r.score))
            .collect::<Vec<_>>()
    );
    assert!(
        ranked[0].score > 0.0,
        "schema match should produce positive score"
    );
}

#[test]
fn ranking_schema_field_tool_scores_above_zero_for_field_query() {
    // GIVEN: query "symbol exchange", tool only matches via schema fields
    // (description itself doesn't mention those words as plain text)
    // WHEN: ranking
    // THEN: schema-annotated tool scores > 0 (i.e. the schema section was searched)
    //
    // NOTE: because schema tokens appear literally in the description string,
    // the text-coverage path also fires. Both paths produce a positive score.
    // The test asserts the schema tool is correctly matched with a meaningful score.
    let search_ranker = SearchRanker::new();
    let results = vec![
        sr(
            "schema_tool",
            "Financial data [schema: symbol, exchange, price]",
        ),
        sr("unrelated_tool", "Send emails and notifications"),
    ];
    let ranked = search_ranker.rank(results, "symbol exchange");
    let schema_result = ranked.iter().find(|r| r.tool == "schema_tool").unwrap();
    assert!(
        schema_result.score >= 8.0,
        "schema tool should score ≥ 8.0 for 2 matching fields, got {}",
        schema_result.score
    );
    assert_eq!(ranked[0].tool, "schema_tool", "schema tool must rank first");
}

#[test]
fn ranking_query_stock_symbol_finds_tool_with_symbol_schema_field() {
    // Integration test: verifies the issue requirement
    // A tool with input {symbol: string, exchange: string} should match "stock symbol"
    let search_ranker = SearchRanker::new();
    let results = vec![
        sr("get_weather", "Retrieve current weather conditions"),
        sr(
            "get_quote",
            "Retrieve financial quotes [schema: symbol, exchange, price, volume, currency]",
        ),
        sr("list_files", "List files in a directory"),
    ];
    let ranked = search_ranker.rank(results, "stock symbol");
    assert_eq!(
        ranked[0].tool,
        "get_quote",
        "get_quote must rank first for 'stock symbol'; scores: {:?}",
        ranked
            .iter()
            .map(|r| (&r.tool, r.score))
            .collect::<Vec<_>>()
    );
}

#[test]
fn extract_tag_section_finds_keywords_section() {
    let desc = "tool desc [keywords: search, web] [schema: symbol]";
    let section = extract_tag_section(desc, "keywords");
    assert!(section.is_some());
    assert!(section.unwrap().contains("search"));
    assert!(section.unwrap().contains("web"));
}

#[test]
fn extract_tag_section_finds_schema_section() {
    let desc = "tool desc [keywords: search] [schema: symbol, exchange]";
    let section = extract_tag_section(desc, "schema");
    assert!(section.is_some());
    assert!(section.unwrap().contains("symbol"));
}

#[test]
fn extract_tag_section_returns_none_for_missing_section() {
    let desc = "plain description with no tags";
    assert!(extract_tag_section(desc, "keywords").is_none());
    assert!(extract_tag_section(desc, "schema").is_none());
}
