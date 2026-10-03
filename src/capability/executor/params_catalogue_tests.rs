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
}

#[test]
fn sentry_list_issues_sends_the_documented_page_size_parameter() {
    let cap = shipped("capabilities/observability/sentry_list_issues.yaml");
    let config = &provider(&cap).config;
    let args = json!({ "organization": "acme", "limit": 10 });

    let pairs = CapabilityExecutor::new()
        .substitute_params(&config.params, &args)
        .unwrap();
    let find = |name: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(find("limit"), Some("10"), "{pairs:?}");
    assert_eq!(
        find("per_page"),
        None,
        "an undocumented parameter: {pairs:?}"
    );
    assert!(
        !config.static_params.contains_key("per_page"),
        "the static default overrides nothing the upstream reads"
    );
    assert!(validate_arguments(&args, &cap.schema.input).is_valid());
}

#[test]
fn sentry_list_issues_accepts_the_array_the_api_returns() {
    let cap = shipped("capabilities/observability/sentry_list_issues.yaml");
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
fn search_outputs_accept_the_extra_fields_and_the_null_answer_upstream_sends() {
    accepts(
        &shipped("capabilities/search/tavily_search.yaml"),
        &json!({
            "query": "mcp", "answer": null, "images": [], "follow_up_questions": null,
            "results": [{ "title": "t", "url": "https://x", "content": "c", "score": 0.9 }],
            "response_time": 1.2, "request_id": "r-1"
        }),
    );
    accepts(
        &shipped("capabilities/search/tavily_search.yaml"),
        &json!({ "answer": "text", "results": [] }),
    );
    accepts(
        &shipped("capabilities/search/tavily_extract.yaml"),
        &json!({
            "results": [{ "url": "https://x", "raw_content": "c", "images": [] }],
            "failed_results": [], "response_time": 0.1, "usage": { "credits": 1 },
            "request_id": "r-2"
        }),
    );
    accepts(
        &shipped("capabilities/search/brave_web_search.yaml"),
        &json!({
            "type": "search", "query": { "original": "mcp" }, "mixed": { "type": "mixed" },
            "web": { "results": [] }, "videos": { "results": [] }
        }),
    );
    accepts(
        &shipped("capabilities/search/brave_news_search.yaml"),
        &json!({ "type": "news", "query": { "original": "mcp" }, "results": [] }),
    );
}
