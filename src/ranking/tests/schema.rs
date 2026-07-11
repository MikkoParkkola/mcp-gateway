use super::*;

#[test]
fn is_schema_field_match_finds_exact_token() {
    let desc = "stock api [schema: symbol, exchange, price]";
    assert!(is_schema_field_match(desc, "symbol"));
    assert!(is_schema_field_match(desc, "exchange"));
    assert!(is_schema_field_match(desc, "price"));
    assert!(!is_schema_field_match(desc, "volume"));
    assert!(!is_schema_field_match(desc, "stock"));
}

#[test]
fn is_schema_field_match_returns_false_when_no_schema_section() {
    assert!(!is_schema_field_match("plain description", "symbol"));
}

#[test]
fn is_schema_field_match_returns_false_for_partial_token() {
    let desc = "tool [schema: symbol, exchange]";
    assert!(!is_schema_field_match(desc, "change"));
    assert!(!is_schema_field_match(desc, "sym"));
}

#[test]
fn score_text_relevance_single_schema_field_scores_6() {
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
        "two-field query ({score_two}) should score >= one-field query ({score_one})"
    );
    assert!(
        score_two >= 8.0,
        "two-field match should score >= 8.0, got {score_two}"
    );
}

#[test]
fn score_text_relevance_schema_scores_above_description_substring() {
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
    assert!(
        schema_score > text_score,
        "schema ({schema_score}) should beat description-text ({text_score})"
    );
}

#[test]
fn score_text_relevance_keyword_tag_beats_schema_match() {
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
        "schema tool should score >= 8.0 for 2 matching fields, got {}",
        schema_result.score
    );
    assert_eq!(ranked[0].tool, "schema_tool", "schema tool must rank first");
}

#[test]
fn ranking_query_stock_symbol_finds_tool_with_symbol_schema_field() {
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
