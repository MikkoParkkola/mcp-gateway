// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! End-to-end `gateway_search` disclosure tests (MIK-7084).

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::Backend;
use crate::backend::BackendRegistry;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::{JsonRpcResponse, RequestId, Tool, ToolsListResult};
use crate::ranking::SearchRanker;
use crate::transport::Transport;

struct SearchTestTransport {
    response: JsonRpcResponse,
}

#[async_trait::async_trait]
impl Transport for SearchTestTransport {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        assert_eq!(method, "tools/list");
        Ok(self.response.clone())
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

fn tool(name: &str, description: &str, schema: Value) -> Tool {
    Tool {
        name: name.to_string(),
        title: None,
        description: Some(description.to_string()),
        input_schema: schema,
        output_schema: None,
        annotations: None,
        role: None,
        projection: None,
    }
}

async fn backend_with_tools(name: &str, tools: Vec<Tool>) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        name,
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let response = JsonRpcResponse::success_serialized(
        RequestId::Number(1),
        ToolsListResult {
            tools,
            next_cursor: None,
        },
    );
    let transport: Arc<dyn Transport> = Arc::new(SearchTestTransport { response });
    backend.set_transport_for_test(transport);
    backend.get_tools_shared().await.unwrap();
    backend
}

fn schema(required: &[&str], properties: &Value) -> Value {
    json!({"type": "object", "properties": properties, "required": required})
}

fn linear_tools() -> Vec<Tool> {
    vec![
        tool(
            "create_issue",
            "Create a Linear issue in a team. Use when filing work. [keywords: linear, issue]",
            schema(
                &["title", "team"],
                &json!({
                    "title": {"type": "string"},
                    "team": {"type": "string"},
                    "description": {"type": "string"},
                    "priority": {"type": "integer"}
                }),
            ),
        ),
        tool(
            "list_issues",
            "List Linear issues in a team. [keywords: linear, list]",
            schema(&["team"], &json!({"team": {"type": "string"}})),
        ),
    ]
}

fn catalog_servers() -> Vec<(&'static str, Vec<Tool>)> {
    vec![
        ("linear", linear_tools()),
        (
            "brave",
            vec![tool(
                "web_search",
                "Search the public web. Prefer this for current events. [keywords: search, web]",
                schema(
                    &["query"],
                    &json!({"query": {"type": "string"}, "count": {"type": "integer"}}),
                ),
            )],
        ),
        (
            "gmail",
            vec![tool(
                "send_email",
                "Send an email from the connected Gmail account. [keywords: email, send]",
                schema(
                    &["to", "subject", "body"],
                    &json!({
                        "to": {"type": "string"},
                        "subject": {"type": "string"},
                        "body": {"type": "string"}
                    }),
                ),
            )],
        ),
        (
            "github",
            vec![tool(
                "create_pull_request",
                "Open a GitHub pull request. Use after pushing a branch. [keywords: github, pr]",
                schema(
                    &["owner", "repo", "title", "head", "base"],
                    &json!({
                        "owner": {"type": "string"},
                        "repo": {"type": "string"},
                        "title": {"type": "string"},
                        "head": {"type": "string"},
                        "base": {"type": "string"}
                    }),
                ),
            )],
        ),
        (
            "google_calendar",
            vec![tool(
                "list_events",
                "List events on a Google Calendar. [keywords: calendar, events]",
                schema(
                    &["calendarId"],
                    &json!({
                        "calendarId": {"type": "string"},
                        "timeMin": {"type": "string"}
                    }),
                ),
            )],
        ),
    ]
}

async fn catalog_meta() -> MetaMcp {
    let registry = Arc::new(BackendRegistry::new());
    for (name, tools) in catalog_servers() {
        let _ = registry.register(backend_with_tools(name, tools).await);
    }
    MetaMcp::with_features(
        registry,
        None,
        None,
        Some(Arc::new(SearchRanker::new())),
        Duration::from_secs(60),
    )
    .with_code_mode(true)
}

const T5_QUERIES: [&str; 5] = [
    "linear create issue",
    "web search",
    "send email",
    "github pull request",
    "calendar events",
];

#[tokio::test]
async fn mik_gw_t3_gateway_search_omits_ranking_unless_explain() {
    let meta = catalog_meta().await;
    let hidden = meta
        .code_mode_search(&json!({ "query": "linear create issue", "limit": 2 }), None)
        .await
        .unwrap();
    let shown = meta
        .code_mode_search(
            &json!({ "query": "linear create issue", "limit": 2, "explain": true }),
            None,
        )
        .await
        .unwrap();
    assert!(hidden["matches"][0].get("ranking").is_none());
    assert!(shown["matches"][0].get("ranking").is_some());
    assert!(shown["matches"][0]["ranking"]["reasons"].is_array());
}

#[tokio::test]
async fn mik_gw_t1_default_is_l0() {
    let meta = catalog_meta().await;
    let result = meta
        .code_mode_search(&json!({ "query": "linear create issue", "limit": 1 }), None)
        .await
        .unwrap();
    let hit = &result["matches"][0];
    let mut keys: Vec<_> = hit.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["description", "score", "tool"]);
    assert!(
        !hit["description"].as_str().unwrap().contains("[keywords:"),
        "L0 purpose must not carry keyword tags: {}",
        hit["description"]
    );
}

#[tokio::test]
async fn mik_gw_t2_detail_and_include_schema_select_tiers() {
    let meta = catalog_meta().await;
    let l1 = meta
        .code_mode_search(
            &json!({ "query": "linear create issue", "limit": 1, "detail": "l1" }),
            None,
        )
        .await
        .unwrap();
    let l1_hit = &l1["matches"][0];
    assert!(l1_hit.get("input_schema").is_none());
    assert!(l1_hit.get("signature").is_some());
    assert!(l1_hit.get("required").is_some());
    assert!(l1_hit.get("when_to_use").is_some());

    let via_legacy = meta
        .code_mode_search(
            &json!({ "query": "linear create issue", "limit": 1, "include_schema": true }),
            None,
        )
        .await
        .unwrap();
    assert!(via_legacy["matches"][0].get("input_schema").is_some());

    let l2 = meta
        .code_mode_search(
            &json!({ "query": "linear create issue", "limit": 1, "detail": "l2" }),
            None,
        )
        .await
        .unwrap();
    assert!(l2["matches"][0].get("input_schema").is_some());
}

#[tokio::test]
async fn mik_gw_t5_l0_top_tool_matches_legacy_full_for_five_queries() {
    let meta = catalog_meta().await;
    for query in T5_QUERIES {
        let l0 = meta
            .code_mode_search(&json!({ "query": query, "limit": 3 }), None)
            .await
            .unwrap();
        let legacy = meta
            .code_mode_search(
                &json!({
                    "query": query,
                    "limit": 3,
                    "detail": "l2",
                    "explain": true
                }),
                None,
            )
            .await
            .unwrap();
        let l0_top = l0["matches"][0]["tool"].as_str().unwrap();
        let legacy_top = legacy["matches"][0]["tool"].as_str().unwrap();
        assert_eq!(
            l0_top, legacy_top,
            "{query}: L0 picked {l0_top}, legacy picked {legacy_top}"
        );
        let l0_names: Vec<_> = l0["matches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["tool"].as_str().unwrap().to_string())
            .collect();
        let legacy_names: Vec<_> = legacy["matches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["tool"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(l0_names, legacy_names, "{query}: order diverged");
    }
}

#[tokio::test]
async fn mik_gw_t2_invalid_detail_fails_fast() {
    let meta = catalog_meta().await;
    let err = meta
        .code_mode_search(&json!({ "query": "linear", "detail": "full" }), None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("l0|l1|l2"), "{err}");
}

// ---------------------------------------------------------------------------
// MIK-3274.RANKING.2 — authorization before disclosure, ranking before truncation
// ---------------------------------------------------------------------------

use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
use std::collections::HashMap;

/// Query used by every ordering fixture below.
const OUTBOUND_QUERY: &str = "send email";

/// Adversarially high usage count fed to the ranker before searching.
const POISON_USES: usize = 4096;

fn outbound_servers() -> Vec<(&'static str, Vec<Tool>)> {
    vec![
        (
            "gmail",
            vec![tool(
                "send_email",
                "Send an email from the connected Gmail account. [keywords: email, send]",
                schema(&["to"], &json!({"to": {"type": "string"}})),
            )],
        ),
        (
            "mailroom",
            vec![
                tool(
                    "email_digest_status",
                    "Report whether the nightly digest finished.",
                    schema(&["day"], &json!({"day": {"type": "string"}})),
                ),
                tool(
                    "send_email",
                    "Deliver a message through the internal relay. [keywords: relay]",
                    schema(&["to"], &json!({"to": {"type": "string"}})),
                ),
            ],
        ),
    ]
}

async fn outbound_meta(profile: Option<ProfileRegistry>) -> MetaMcp {
    let registry = Arc::new(BackendRegistry::new());
    for (name, tools) in outbound_servers() {
        let _ = registry.register(backend_with_tools(name, tools).await);
    }
    let ranker = Arc::new(SearchRanker::new());
    for _ in 0..POISON_USES {
        ranker.record_use("gmail", "send_email");
        ranker.record_use("mailroom", "email_digest_status");
    }
    let meta = MetaMcp::with_features(registry, None, None, Some(ranker), Duration::from_secs(60))
        .with_code_mode(true);
    match profile {
        Some(registry) => meta.with_profile_registry(registry),
        None => meta,
    }
}

fn deny_gmail_profile() -> ProfileRegistry {
    let mut configs = HashMap::new();
    configs.insert(
        "restricted".to_string(),
        RoutingProfileConfig {
            deny_backends: Some(vec!["gmail".to_string()]),
            ..RoutingProfileConfig::default()
        },
    );
    ProfileRegistry::from_config(&configs, "restricted")
}

/// Collect `"server:tool"` refs from a Code Mode search response.
fn code_mode_refs(response: &Value) -> Vec<String> {
    response["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["tool"].as_str().unwrap().to_string())
        .collect()
}

/// Collect `"server:tool"` refs from a `gateway_search_tools` response.
fn search_tools_refs(response: &Value) -> Vec<String> {
    response["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            format!(
                "{}:{}",
                m["server"].as_str().unwrap(),
                m["tool"].as_str().unwrap()
            )
        })
        .collect()
}

#[tokio::test]
async fn mik_gw_ranking2_code_mode_filters_forbidden_before_disclosure() {
    // Counterfactual: with no profile the forbidden tool is not merely present,
    // its poisoned usage puts it first — so its absence below is authorization,
    // not a ranking accident.
    let open = outbound_meta(None).await;
    let open_hits = open
        .code_mode_search(&json!({"query": OUTBOUND_QUERY, "limit": 10}), None)
        .await
        .unwrap();
    assert_eq!(code_mode_refs(&open_hits)[0], "gmail:send_email");
    assert_eq!(open_hits["total_available"], 3);

    // Restricted: a wide limit leaves room for the forbidden tool, so absence
    // cannot be blamed on truncation.
    let closed = outbound_meta(Some(deny_gmail_profile())).await;
    let closed_hits = closed
        .code_mode_search(&json!({"query": OUTBOUND_QUERY, "limit": 10}), None)
        .await
        .unwrap();
    let refs = code_mode_refs(&closed_hits);
    assert!(
        !refs.iter().any(|r| r.starts_with("gmail:")),
        "forbidden backend disclosed: {refs:?}"
    );
    assert!(
        refs.contains(&"mailroom:send_email".to_string()),
        "{refs:?}"
    );
    // Pre-truncation candidate count also drops: the filter runs before the
    // catalogue is counted, not after it is trimmed.
    assert_eq!(closed_hits["total_available"], 2);
}

#[tokio::test]
async fn mik_gw_ranking2_code_mode_ranks_before_truncating() {
    let meta = outbound_meta(Some(deny_gmail_profile())).await;

    // Pre-ranking order, measured through the glob path (which skips the
    // ranker): the weak tool is collected first, so truncating before ranking
    // would return it.
    let unranked = meta
        .code_mode_search(&json!({"query": "*mail*", "limit": 10}), None)
        .await
        .unwrap();
    assert_eq!(
        code_mode_refs(&unranked),
        vec!["mailroom:email_digest_status", "mailroom:send_email"]
    );

    let hits = meta
        .code_mode_search(&json!({"query": OUTBOUND_QUERY, "limit": 1}), None)
        .await
        .unwrap();
    assert_eq!(code_mode_refs(&hits), vec!["mailroom:send_email"]);
    assert_eq!(hits["total"], 1);
    assert_eq!(hits["total_available"], 2);

    // The loser really did carry the poisoned feedback and still lost.
    let explained = meta
        .code_mode_search(
            &json!({"query": OUTBOUND_QUERY, "limit": 10, "explain": true}),
            None,
        )
        .await
        .unwrap();
    let matches = explained["matches"].as_array().unwrap();
    assert_eq!(matches[0]["ranking"]["signals"]["usage_count"], 0);
    assert_eq!(
        matches[1]["ranking"]["signals"]["usage_count"],
        POISON_USES as u64
    );
    assert!(
        matches[1]["ranking"]["signals"]["relevance"]
            .as_f64()
            .unwrap()
            < 6.0
    );
}

#[tokio::test]
async fn mik_gw_ranking2_search_tools_filters_forbidden_before_disclosure() {
    let open = outbound_meta(None).await;
    let open_hits = open
        .search_tools(&json!({"query": OUTBOUND_QUERY, "limit": 10}), None)
        .await
        .unwrap();
    assert_eq!(search_tools_refs(&open_hits)[0], "gmail:send_email");
    assert_eq!(open_hits["total_available"], 3);

    let closed = outbound_meta(Some(deny_gmail_profile())).await;
    let closed_hits = closed
        .search_tools(&json!({"query": OUTBOUND_QUERY, "limit": 10}), None)
        .await
        .unwrap();
    let refs = search_tools_refs(&closed_hits);
    assert!(
        !refs.iter().any(|r| r.starts_with("gmail:")),
        "forbidden backend disclosed: {refs:?}"
    );
    assert!(
        refs.contains(&"mailroom:send_email".to_string()),
        "{refs:?}"
    );
    assert_eq!(closed_hits["total_available"], 2);
}

#[tokio::test]
async fn mik_gw_ranking2_search_tools_ranks_before_truncating() {
    let meta = outbound_meta(Some(deny_gmail_profile())).await;

    let hits = meta
        .search_tools(&json!({"query": OUTBOUND_QUERY, "limit": 1}), None)
        .await
        .unwrap();
    assert_eq!(search_tools_refs(&hits), vec!["mailroom:send_email"]);
    assert_eq!(hits["total"], 1);
    assert_eq!(hits["total_available"], 2);

    let explained = meta
        .search_tools(
            &json!({"query": OUTBOUND_QUERY, "limit": 10, "explain": true}),
            None,
        )
        .await
        .unwrap();
    let matches = explained["matches"].as_array().unwrap();
    assert_eq!(matches[0]["ranking"]["signals"]["usage_count"], 0);
    assert_eq!(
        matches[1]["ranking"]["signals"]["usage_count"],
        POISON_USES as u64
    );
}
