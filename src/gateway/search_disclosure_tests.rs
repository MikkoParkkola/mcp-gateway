// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::{
    ONE_LINE_MAX, SearchDetail, SearchDisclosure, one_line_purpose, project_code_mode_match,
    ranking_debug_object, required_params, resolve_search_disclosure, schema_signature,
    when_to_use,
};
use crate::ranking::{RankingExplanation, SearchResult};
use serde_json::{Value, json};

fn keys_of(value: &Value) -> Vec<String> {
    value
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

fn fat_linear_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "Issue title. Deprecated alias headline is accepted for one release and will be removed; do not send both."
            },
            "team": { "type": "string", "description": "Team key or UUID" },
            "description": { "type": "string", "description": "Markdown body" },
            "assigneeId": { "type": "string" },
            "priority": { "type": "integer" },
            "labelIds": { "type": "array", "items": { "type": "string" } },
            "parentId": { "type": "string" },
            "cycleId": { "type": "string" },
            "projectId": { "type": "string" },
            "stateId": { "type": "string" },
            "dueDate": { "type": "string" },
            "estimate": { "type": "number" },
            "subscriberIds": { "type": "array", "items": { "type": "string" } },
            "headline": {
                "type": "string",
                "description": "Deprecated. Use title instead. Kept so existing callers that still send headline do not break; remove after 2026-12-01. This paragraph exists to reproduce the deprecation-essay waste measured on the live gateway."
            }
        },
        "required": ["title", "team"]
    })
}

fn ranked_match(tool: &str, description: &str, schema: &Value, score: f64) -> Value {
    let mut result = SearchResult::new("srv", "t", description);
    result.score = score;
    result.explanation = RankingExplanation {
        included: true,
        reasons: vec![
            "intent_match".into(),
            "safety_ok".into(),
            "grant_ok".into(),
            "risk_fit".into(),
            "policy_fit".into(),
            "permission_fit".into(),
            "trust_ok".into(),
            "cost_fit".into(),
            "latency_fit".into(),
            "success_rate_fit".into(),
            "user_preference_fit".into(),
            "organization_preference_fit".into(),
        ],
    };
    result.signals.relevance = 0.8;
    json!({
        "tool": tool,
        "description": description,
        "input_schema": schema,
        "score": score,
        "ranking": ranking_debug_object(&result)
    })
}

fn envelope(query: &str, matches: &[Value]) -> Value {
    json!({
        "query": query,
        "matches": matches,
        "total": matches.len(),
        "total_available": matches.len()
    })
}

fn utf8_len(value: &Value) -> usize {
    serde_json::to_vec(value).expect("serialize").len()
}

// ── MIK.GW.T2 resolve ────────────────────────────────────────────────

#[test]
fn default_args_resolve_to_l0_without_explain() {
    let d = resolve_search_disclosure(&json!({ "query": "x" })).unwrap();
    assert_eq!(d.detail, SearchDetail::L0);
    assert!(!d.explain);
}

#[test]
fn include_schema_true_maps_to_l2() {
    let d = resolve_search_disclosure(&json!({ "include_schema": true })).unwrap();
    assert_eq!(d.detail, SearchDetail::L2);
}

#[test]
fn include_schema_false_maps_to_l0() {
    let d = resolve_search_disclosure(&json!({ "include_schema": false })).unwrap();
    assert_eq!(d.detail, SearchDetail::L0);
}

#[test]
fn explicit_detail_wins_over_include_schema() {
    let d = resolve_search_disclosure(&json!({
        "detail": "l1",
        "include_schema": true
    }))
    .unwrap();
    assert_eq!(d.detail, SearchDetail::L1);
}

#[test]
fn detail_is_case_insensitive() {
    assert_eq!(
        resolve_search_disclosure(&json!({ "detail": "L2" }))
            .unwrap()
            .detail,
        SearchDetail::L2
    );
}

#[test]
fn invalid_detail_is_protocol_error() {
    let err = resolve_search_disclosure(&json!({ "detail": "full" })).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("l0|l1|l2"), "{msg}");
}

#[test]
fn non_string_detail_is_protocol_error() {
    assert!(resolve_search_disclosure(&json!({ "detail": 2 })).is_err());
}

#[test]
fn explain_true_is_opt_in() {
    let d = resolve_search_disclosure(&json!({ "explain": true })).unwrap();
    assert!(d.explain);
    assert_eq!(d.detail, SearchDetail::L0);
}

// ── MIK.GW.T1 / T2 projection ────────────────────────────────────────

#[test]
fn l0_keeps_only_tool_description_score() {
    let src = ranked_match(
        "linear:create_issue",
        "Create a Linear issue. Use when filing a ticket. [keywords: linear, issue]",
        &fat_linear_schema(),
        12.4,
    );
    let out = project_code_mode_match(
        src,
        SearchDisclosure {
            detail: SearchDetail::L0,
            explain: false,
        },
    );
    let mut keys = keys_of(&out);
    keys.sort();
    assert_eq!(keys, ["description", "score", "tool"]);
    assert_eq!(out["tool"], "linear:create_issue");
    assert_eq!(out["score"], 12.4);
    assert_eq!(out["description"], "Create a Linear issue.");
    assert!(out.get("ranking").is_none());
    assert!(out.get("input_schema").is_none());
}

#[test]
fn l0_omits_disabled_status() {
    let src = json!({
        "tool": "x:y",
        "description": "Does Y.",
        "score": 1.0,
        "status": "disabled",
        "input_schema": {"type": "object"}
    });
    let out = project_code_mode_match(
        src,
        SearchDisclosure {
            detail: SearchDetail::L0,
            explain: false,
        },
    );
    assert!(out.get("status").is_none());
}

#[test]
fn l1_adds_signature_when_to_use_required_and_drops_schema() {
    let src = ranked_match(
        "linear:create_issue",
        "Create a Linear issue.\n\nLonger planning notes that belong at L1.",
        &fat_linear_schema(),
        9.0,
    );
    let out = project_code_mode_match(
        src,
        SearchDisclosure {
            detail: SearchDetail::L1,
            explain: false,
        },
    );
    assert!(out.get("input_schema").is_none());
    assert!(out.get("ranking").is_none());
    assert_eq!(out["required"], json!(["title", "team"]));
    let sig = out["signature"].as_str().unwrap();
    assert!(sig.starts_with("title: string, team: string"), "{sig}");
    assert!(sig.contains("headline?: string"), "{sig}");
    assert_eq!(out["when_to_use"], "Create a Linear issue.");
}

#[test]
fn l2_keeps_input_schema_and_full_description() {
    let desc = "Create a Linear issue. Use when filing a ticket.";
    let src = ranked_match("linear:create_issue", desc, &fat_linear_schema(), 9.0);
    let out = project_code_mode_match(
        src,
        SearchDisclosure {
            detail: SearchDetail::L2,
            explain: false,
        },
    );
    assert!(out.get("input_schema").is_some());
    assert_eq!(out["description"], desc);
    assert!(out.get("ranking").is_none());
    assert!(out.get("signature").is_none());
}

#[test]
fn explain_true_keeps_ranking_at_every_tier() {
    let src = ranked_match("s:t", "Short purpose.", &fat_linear_schema(), 1.0);
    for detail in [SearchDetail::L0, SearchDetail::L1, SearchDetail::L2] {
        let out = project_code_mode_match(
            src.clone(),
            SearchDisclosure {
                detail,
                explain: true,
            },
        );
        assert!(
            out.get("ranking").is_some(),
            "ranking missing at {detail:?}"
        );
        assert_eq!(out["ranking"]["included"], true);
        assert!(out["ranking"]["reasons"].as_array().unwrap().len() >= 12);
    }
}

#[test]
fn l0_description_never_exceeds_one_line_cap() {
    let long = "A".repeat(400);
    let src = json!({
        "tool": "s:t",
        "description": long,
        "score": 1.0,
        "input_schema": {"type": "object"}
    });
    let out = project_code_mode_match(
        src,
        SearchDisclosure {
            detail: SearchDetail::L0,
            explain: false,
        },
    );
    let desc = out["description"].as_str().unwrap();
    assert!(desc.chars().count() <= ONE_LINE_MAX, "{desc}");
    assert!(desc.ends_with("..."));
}

// ── purpose / signature helpers ──────────────────────────────────────

#[test]
fn one_line_purpose_strips_keywords_and_takes_first_sentence() {
    assert_eq!(
        one_line_purpose("Create an issue. Extra prose. [keywords: linear, issue]"),
        "Create an issue."
    );
}

#[test]
fn when_to_use_stops_at_blank_line() {
    assert_eq!(
        when_to_use("File a ticket.\n\nImplementation notes live here."),
        "File a ticket."
    );
}

#[test]
fn required_params_reads_schema_required() {
    assert_eq!(
        required_params(&fat_linear_schema()),
        vec!["title".to_string(), "team".to_string()]
    );
    assert!(required_params(&json!({"type": "object"})).is_empty());
}

#[test]
fn schema_signature_marks_optional_params() {
    let sig = schema_signature(&json!({
        "type": "object",
        "properties": {
            "q": {"type": "string"},
            "limit": {"type": "integer"}
        },
        "required": ["q"]
    }));
    assert_eq!(sig, "q: string, limit?: integer");
}

#[test]
fn schema_signature_empty_without_properties() {
    assert_eq!(schema_signature(&json!({"type": "object"})), "");
}

// ── MIK.GW.T3 measurement on a lean two-hit payload ──────────────────

#[test]
fn mik_gw_t3_ranking_blob_is_majority_of_lean_payload() {
    let lean = json!({
        "tool": "linear:save_issue",
        "description": "Create a new issue in Linear. Use this when the user wants to file a ticket.",
        "score": 12.4
    });
    let ranked = ranked_match(
        "linear:save_issue",
        "Create a new issue in Linear. Use this when the user wants to file a ticket.",
        &json!({"type": "object"}),
        12.4,
    );
    // Lean Code Mode match has no schema; ranking attached as today.
    let with_ranking = json!({
        "tool": ranked["tool"],
        "description": ranked["description"],
        "score": ranked["score"],
        "ranking": ranked["ranking"]
    });
    let without = envelope("linear create", &[lean.clone(), lean]);
    let with = envelope("linear create", &[with_ranking.clone(), with_ranking]);
    let lean_n = utf8_len(&without);
    let with_n = utf8_len(&with);
    let ranking_bytes = with_n.saturating_sub(lean_n);
    assert!(
        ranking_bytes.saturating_mul(100) >= with_n.saturating_mul(45),
        "T3 fail-fast: ranking {ranking_bytes}/{with_n} is far below ~60% (lean={lean_n})"
    );
}

// ── MIK.GW.T4 / T5 on fixture catalog ────────────────────────────────

fn catalog_hits() -> Vec<(&'static str, Value)> {
    vec![
        (
            "linear create issue",
            ranked_match(
                "linear:create_issue",
                "Create a Linear issue in a team. Use when filing work. [keywords: linear, issue]",
                &fat_linear_schema(),
                14.0,
            ),
        ),
        (
            "web search",
            ranked_match(
                "brave:web_search",
                "Search the public web. Prefer this for current events. [keywords: search, web]",
                &json!({
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query"},
                        "count": {"type": "integer"},
                        "country": {"type": "string"},
                        "search_lang": {"type": "string"},
                        "ui_lang": {"type": "string"},
                        "freshness": {"type": "string"}
                    },
                    "required": ["query"]
                }),
                13.0,
            ),
        ),
        (
            "send email",
            ranked_match(
                "gmail:send_email",
                "Send an email from the connected Gmail account. [keywords: email, send]",
                &json!({
                    "type": "object",
                    "properties": {
                        "to": {"type": "string"},
                        "subject": {"type": "string"},
                        "body": {"type": "string"},
                        "cc": {"type": "string"},
                        "bcc": {"type": "string"},
                        "threadId": {"type": "string"},
                        "attachments": {"type": "array"}
                    },
                    "required": ["to", "subject", "body"]
                }),
                12.0,
            ),
        ),
        (
            "github pull request",
            ranked_match(
                "github:create_pull_request",
                "Open a GitHub pull request. Use after pushing a branch. [keywords: github, pr]",
                &json!({
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string"},
                        "repo": {"type": "string"},
                        "title": {"type": "string"},
                        "head": {"type": "string"},
                        "base": {"type": "string"},
                        "body": {"type": "string"},
                        "draft": {"type": "boolean"},
                        "maintainer_can_modify": {"type": "boolean"}
                    },
                    "required": ["owner", "repo", "title", "head", "base"]
                }),
                11.0,
            ),
        ),
        (
            "calendar events",
            ranked_match(
                "google_calendar:list_events",
                "List events on a Google Calendar. [keywords: calendar, events]",
                &json!({
                    "type": "object",
                    "properties": {
                        "calendarId": {"type": "string"},
                        "timeMin": {"type": "string"},
                        "timeMax": {"type": "string"},
                        "maxResults": {"type": "integer"},
                        "q": {"type": "string"},
                        "singleEvents": {"type": "boolean"},
                        "orderBy": {"type": "string"}
                    },
                    "required": ["calendarId"]
                }),
                10.0,
            ),
        ),
    ]
}

fn project_hits(hits: &[Value], disclosure: SearchDisclosure) -> Vec<Value> {
    hits.iter()
        .cloned()
        .map(|m| project_code_mode_match(m, disclosure))
        .collect()
}

#[test]
fn mik_gw_t4_l0_is_at_most_a_quarter_of_legacy_default() {
    let catalog = catalog_hits();
    let mut rows = Vec::new();
    for (query, hit) in &catalog {
        let hits = vec![hit.clone()];
        let legacy_hits = project_hits(
            &hits,
            SearchDisclosure {
                detail: SearchDetail::L2,
                explain: true,
            },
        );
        let l0_hits = project_hits(
            &hits,
            SearchDisclosure {
                detail: SearchDetail::L0,
                explain: false,
            },
        );
        let l1_hits = project_hits(
            &hits,
            SearchDisclosure {
                detail: SearchDetail::L1,
                explain: false,
            },
        );
        let l2_hits = project_hits(
            &hits,
            SearchDisclosure {
                detail: SearchDetail::L2,
                explain: false,
            },
        );
        let legacy = envelope(query, &legacy_hits);
        let l0 = envelope(query, &l0_hits);
        let l1 = envelope(query, &l1_hits);
        let l2 = envelope(query, &l2_hits);
        let legacy_n = utf8_len(&legacy);
        let l0_n = utf8_len(&l0);
        rows.push((*query, legacy_n, l0_n, utf8_len(&l1), utf8_len(&l2)));
        assert!(
            l0_n.saturating_mul(4) <= legacy_n,
            "{query}: L0 {l0_n} is more than 25% of legacy {legacy_n}"
        );
    }
    eprintln!("MIK.GW.T4 bytes (legacy=L2+explain, tokens~bytes/4)");
    for (q, legacy, l0, l1, l2) in &rows {
        eprintln!(
            "  {q}: legacy={legacy} (~{} tok) l0={l0} (~{} tok) l1={l1} l2={l2} l0/legacy={}%",
            legacy.div_ceil(4),
            l0.div_ceil(4),
            l0.saturating_mul(100) / (*legacy).max(1)
        );
    }
}

#[test]
fn mik_gw_t5_l0_selects_the_same_tool_as_legacy_full() {
    for (query, hit) in catalog_hits() {
        let expected = hit["tool"].as_str().unwrap().to_string();
        let l0 = project_code_mode_match(
            hit.clone(),
            SearchDisclosure {
                detail: SearchDetail::L0,
                explain: false,
            },
        );
        let legacy = project_code_mode_match(
            hit,
            SearchDisclosure {
                detail: SearchDetail::L2,
                explain: true,
            },
        );
        assert_eq!(
            l0["tool"], legacy["tool"],
            "{query}: L0 picked {} legacy picked {}",
            l0["tool"], legacy["tool"]
        );
        assert_eq!(l0["tool"], expected);
    }
}
