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
