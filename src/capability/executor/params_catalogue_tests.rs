// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7845: the shipped search and Sentry capabilities render the request the
//! upstream documents and accept the responses it really sends.

use serde_json::{Value, json};

use super::super::CapabilityExecutor;
use crate::capability::{
    CapabilityDefinition, definition::ProviderConfig, parse_capability, validate_arguments,
    validate_output,
};

fn shipped(relative: &str) -> CapabilityDefinition {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{relative}: {e}"));
    parse_capability(&yaml).unwrap_or_else(|e| panic!("{relative}: {e}"))
}

fn provider(cap: &CapabilityDefinition) -> &ProviderConfig {
    cap.primary_provider().expect("a primary provider")
}

fn accepts(cap: &CapabilityDefinition, response: &Value) {
    let verdict = validate_output(response, &cap.schema.output);
    assert!(
        verdict.is_valid(),
        "{}: a real response warns: {}",
        cap.name,
        verdict.format_output_error(&cap.schema.output)
    );
    // And what the caller then receives still holds every field upstream sent.
    assert_eq!(
        &verdict.coerced, response,
        "{}: the validated output lost fields",
        cap.name
    );
}

#[test]
fn sentry_list_issues_sends_the_documented_page_size_parameter() {
    let cap = shipped("capabilities/observability/sentry_list_issues.yaml");
    let config = &provider(&cap).config;
    let render = |args: Value| {
        let merged = config.merge_with_static_params(&args);
        CapabilityExecutor::new()
            .substitute_params(&config.params, merged.as_ref())
            .unwrap()
    };
    let find = |pairs: &[(String, String)], name: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };

    let named = render(json!({ "organization": "acme", "limit": 10 }));
    assert_eq!(find(&named, "limit").as_deref(), Some("10"), "{named:?}");
    assert_eq!(
        find(&named, "per_page"),
        None,
        "an undocumented parameter: {named:?}"
    );

    // Left out, the page size is the one the schema advertises, not Sentry's own.
    let omitted = render(json!({ "organization": "acme" }));
    assert_eq!(
        find(&omitted, "limit").as_deref(),
        Some("25"),
        "{omitted:?}"
    );
    assert_eq!(find(&omitted, "per_page"), None, "{omitted:?}");

    let args = json!({ "organization": "acme", "limit": 10 });
    assert!(validate_arguments(&args, &cap.schema.input).is_valid());
}

#[test]
fn sentry_list_issues_accepts_the_array_the_api_returns() {
    let cap = shipped("capabilities/observability/sentry_list_issues.yaml");
    // The API answers with a bare array, and the schema says so.
    assert_eq!(cap.schema.output["type"], "array");
    assert_eq!(cap.schema.output["items"]["additionalProperties"], true);
    accepts(
        &cap,
        &json!([{
            "id": "4815162342", "shortId": "WEB-1A", "title": "TypeError", "level": "error",
            "count": "12", "userCount": 3, "firstSeen": "2026-10-01T00:00:00Z",
            "project": { "id": "1", "slug": "web" }, "permalink": "https://sentry.io/x"
        }]),
    );
}

#[test]
fn sentry_get_issue_takes_the_id_as_a_string() {
    let cap = shipped("capabilities/observability/sentry_get_issue.yaml");
    for id in ["4815162342", "99999999999999999999999"] {
        let args = json!({ "organization": "acme", "issue_id": id });
        let verdict = validate_arguments(&args, &cap.schema.input);
        assert!(
            verdict.is_valid(),
            "{id}: {}",
            verdict.format_error(&cap.schema.input)
        );
        // The ID reaches the URL digit for digit, however long.
        let url = CapabilityExecutor::new()
            .build_url(&provider(&cap).config, &args)
            .unwrap();
        assert_eq!(
            url,
            format!("https://sentry.io/api/0/organizations/acme/issues/{id}/")
        );
    }
}

#[test]
fn sentry_setup_text_names_only_the_scope_the_calls_need() {
    for file in ["sentry_get_issue", "sentry_list_issues"] {
        let cap = shipped(&format!("capabilities/observability/{file}.yaml"));
        let text = cap.auth.description.clone();
        assert!(text.contains("event:read"), "{file}: {text}");
        assert!(
            !text.contains("org:read"),
            "{file} asks for an unneeded scope: {text}"
        );
    }
}

#[test]
fn tavily_search_accepts_extra_fields_and_a_null_answer() {
    let cap = shipped("capabilities/search/tavily_search.yaml");
    accepts(
        &cap,
        &json!({
            "query": "mcp", "answer": null, "images": [], "follow_up_questions": null,
            "results": [{ "title": "t", "url": "https://x", "content": "c", "score": 0.9 }],
            "response_time": 1.2, "request_id": "r-1"
        }),
    );
    accepts(&cap, &json!({ "answer": "text", "results": [] }));
}

#[test]
fn tavily_extract_accepts_the_usage_and_request_fields() {
    accepts(
        &shipped("capabilities/search/tavily_extract.yaml"),
        &json!({
            "results": [{ "url": "https://x", "raw_content": "c", "images": [] }],
            "failed_results": [], "response_time": 0.1, "usage": { "credits": 1 },
            "request_id": "r-2"
        }),
    );
}

#[test]
fn brave_web_search_accepts_the_extra_sections() {
    accepts(
        &shipped("capabilities/search/brave_web_search.yaml"),
        &json!({
            "type": "search", "query": { "original": "mcp" }, "mixed": { "type": "mixed" },
            "web": { "results": [] }, "videos": { "results": [] }
        }),
    );
}

#[test]
fn brave_news_search_accepts_the_type_and_query_fields() {
    accepts(
        &shipped("capabilities/search/brave_news_search.yaml"),
        &json!({ "type": "news", "query": { "original": "mcp" }, "results": [] }),
    );
}

/// MIK-7943 finding 5: Sentry issue IDs start at 1, so a zero or a leading
/// zero never goes upstream.
#[test]
fn sentry_get_issue_refuses_a_zero_id() {
    let cap = shipped("capabilities/observability/sentry_get_issue.yaml");
    for id in ["0", "007"] {
        let args = json!({ "organization": "acme", "issue_id": id });
        let verdict = validate_arguments(&args, &cap.schema.input);
        assert!(!verdict.is_valid(), "{id} accepted");
    }
}

/// What the executor sends for a REST capability: the URL, the query pairs
/// and the JSON body, built by the same steps `execute_rest` takes (static
/// params merged, URL defaults applied, then each part substituted).
fn rendered(cap: &CapabilityDefinition, args: &Value) -> (String, Vec<(String, String)>, Value) {
    let config = &provider(cap).config;
    let merged = config.merge_with_static_params(args);
    let params = super::with_path_defaults(config, &cap.schema.input, merged.as_ref());
    let executor = CapabilityExecutor::new();
    let url = executor.build_url(config, &params).unwrap();
    let mut query = executor.substitute_params(&config.params, &params).unwrap();
    query.sort();
    let body = config.body.as_ref().map_or(Value::Null, |template| {
        executor.substitute_value(template, &params).unwrap()
    });
    (url, query, body)
}

fn pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut pairs: Vec<_> = expected
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    pairs.sort();
    pairs
}

/// MIK-7850.TESTS.1: each #2721 capability renders the request its upstream
/// documents, with every argument given and with only the required one.
#[test]
fn tavily_search_posts_the_documented_body() {
    let cap = shipped("capabilities/search/tavily_search.yaml");
    assert_eq!(provider(&cap).config.method, "POST");
    let args = json!({
        "query": "mcp", "max_results": 3, "search_depth": "advanced",
        "topic": "news", "include_answer": true
    });
    let (url, query, body) = rendered(&cap, &args);
    assert_eq!(url, "https://api.tavily.com/search");
    assert!(query.is_empty(), "{query:?}");
    assert_eq!(body, args, "every argument goes in the body, typed");

    let (_, _, body) = rendered(&cap, &json!({ "query": "mcp" }));
    assert_eq!(
        body,
        json!({ "query": "mcp", "max_results": 5 }),
        "only the static page size joins an omitted argument"
    );
}

#[test]
fn tavily_extract_posts_the_url_list() {
    let cap = shipped("capabilities/search/tavily_extract.yaml");
    assert_eq!(provider(&cap).config.method, "POST");
    let args =
        json!({ "urls": ["https://a.example", "https://b.example"], "extract_depth": "advanced" });
    let (url, query, body) = rendered(&cap, &args);
    assert_eq!(url, "https://api.tavily.com/extract");
    assert!(query.is_empty(), "{query:?}");
    assert_eq!(body, args, "the URL list stays an array");

    let (_, _, body) = rendered(&cap, &json!({ "urls": ["https://a.example"] }));
    assert_eq!(body, json!({ "urls": ["https://a.example"] }));
}

#[test]
fn firecrawl_search_posts_query_and_limit() {
    let cap = shipped("capabilities/search/firecrawl_search.yaml");
    assert_eq!(provider(&cap).config.method, "POST");
    let (url, query, body) = rendered(&cap, &json!({ "query": "mcp", "limit": 2 }));
    assert_eq!(url, "https://api.firecrawl.dev/v2/search");
    assert!(query.is_empty(), "{query:?}");
    assert_eq!(body, json!({ "query": "mcp", "limit": 2 }));

    let (_, _, body) = rendered(&cap, &json!({ "query": "mcp" }));
    assert_eq!(body, json!({ "query": "mcp", "limit": 5 }));
}

#[test]
fn firecrawl_scrape_posts_markdown_format_and_main_content_flag() {
    let cap = shipped("capabilities/search/firecrawl_scrape.yaml");
    assert_eq!(provider(&cap).config.method, "POST");
    let (url, query, body) = rendered(
        &cap,
        &json!({ "url": "https://a.example", "only_main_content": false }),
    );
    assert_eq!(url, "https://api.firecrawl.dev/v2/scrape");
    assert!(query.is_empty(), "{query:?}");
    assert_eq!(
        body,
        json!({ "url": "https://a.example", "formats": ["markdown"], "onlyMainContent": false }),
        "the snake_case argument goes out under Firecrawl's camelCase name"
    );

    let (_, _, body) = rendered(&cap, &json!({ "url": "https://a.example" }));
    assert_eq!(
        body,
        json!({ "url": "https://a.example", "formats": ["markdown"] })
    );
}

#[test]
fn brave_web_search_sends_the_documented_query_parameters() {
    let cap = shipped("capabilities/search/brave_web_search.yaml");
    assert_eq!(provider(&cap).config.method, "GET");
    let (url, query, body) = rendered(
        &cap,
        &json!({ "q": "mcp", "count": 3, "country": "fi", "freshness": "pw" }),
    );
    assert_eq!(url, "https://api.search.brave.com/res/v1/web/search");
    assert_eq!(
        query,
        pairs(&[
            ("q", "mcp"),
            ("count", "3"),
            ("country", "fi"),
            ("freshness", "pw")
        ])
    );
    assert_eq!(body, Value::Null, "a GET sends no body");

    let (_, query, _) = rendered(&cap, &json!({ "q": "mcp" }));
    assert_eq!(query, pairs(&[("q", "mcp"), ("count", "10")]));
}

#[test]
fn brave_news_search_sends_the_documented_query_parameters() {
    let cap = shipped("capabilities/search/brave_news_search.yaml");
    assert_eq!(provider(&cap).config.method, "GET");
    let (url, query, body) = rendered(&cap, &json!({ "q": "mcp", "count": 4, "freshness": "pd" }));
    assert_eq!(url, "https://api.search.brave.com/res/v1/news/search");
    assert_eq!(
        query,
        pairs(&[("q", "mcp"), ("count", "4"), ("freshness", "pd")])
    );
    assert_eq!(body, Value::Null, "a GET sends no body");

    let (_, query, _) = rendered(&cap, &json!({ "q": "mcp" }));
    assert_eq!(query, pairs(&[("q", "mcp"), ("count", "10")]));
}

/// MIK-7850.TESTS.1: the response shapes not covered above.
#[test]
fn firecrawl_search_accepts_the_v2_response() {
    accepts(
        &shipped("capabilities/search/firecrawl_search.yaml"),
        &json!({
            "success": true,
            "data": { "web": [{ "url": "https://a.example", "title": "t", "description": "d", "position": 1 }] },
            "creditsUsed": 2, "id": "s-1"
        }),
    );
}

#[test]
fn firecrawl_scrape_accepts_the_v2_response() {
    accepts(
        &shipped("capabilities/search/firecrawl_scrape.yaml"),
        &json!({
            "success": true,
            "data": {
                "markdown": "# A", "metadata": { "title": "A", "sourceURL": "https://a.example", "statusCode": 200 }
            }
        }),
    );
}

#[test]
fn sentry_get_issue_accepts_the_issue_object() {
    accepts(
        &shipped("capabilities/observability/sentry_get_issue.yaml"),
        &json!({
            "id": "4815162342", "shortId": "WEB-1A", "title": "TypeError", "culprit": "app.js",
            "level": "error", "status": "unresolved", "count": "12", "userCount": 3,
            "firstSeen": "2026-10-01T00:00:00Z", "lastSeen": "2026-10-02T00:00:00Z",
            "project": { "id": "1", "slug": "web" }, "permalink": "https://sentry.io/x"
        }),
    );
}
