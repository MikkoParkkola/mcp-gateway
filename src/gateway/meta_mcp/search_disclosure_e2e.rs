// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! End-to-end `gateway_search` disclosure tests (MIK-7084).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::Backend;
use crate::backend::BackendRegistry;
use crate::config::{BackendConfig, FailsafeConfig, SurfacedToolConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::authz_tests::ctx;
use crate::protocol::{JsonRpcResponse, RequestId, Tool, ToolsListResult};
use crate::ranking::SearchRanker;
use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
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

// ============================================================================
// MIK-7332.DISCOVERY.1 — authorization-derived exposure, tiered disclosure,
// schema validity and configured surfaced tools together on the served
// consumer surface, with the disclosed set matching the invocable set.
// ============================================================================

/// A backend transport that answers both `tools/list` (from a fixed
/// catalogue, to warm the cache real `tools/list` handling reads) and
/// `tools/call` (counting the calls that actually reach it), so one fixture
/// can prove a tool's disclosure and its invocation agree.
struct ServedSurfaceTransport {
    list_response: JsonRpcResponse,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Transport for ServedSurfaceTransport {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        match method {
            "tools/list" => Ok(self.list_response.clone()),
            "tools/call" => {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(JsonRpcResponse::success_serialized(
                    RequestId::Number(1),
                    json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
                ))
            }
            other => panic!("unexpected method {other}"),
        }
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

async fn served_surface_backend(name: &str, tools: Vec<Tool>, calls: Arc<AtomicUsize>) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        name,
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let list_response = JsonRpcResponse::success_serialized(
        RequestId::Number(1),
        ToolsListResult {
            tools,
            next_cursor: None,
        },
    );
    let transport: Arc<dyn Transport> = Arc::new(ServedSurfaceTransport {
        list_response,
        calls,
    });
    backend.set_transport_for_test(transport);
    backend.get_tools_shared().await.unwrap();
    backend
}

/// Traditional-mode surface: `tools/list` composes the meta-tool exposure
/// allow-list, the routing profile, configured surfaced tools and the
/// trust-card schema projection in one response
/// (`MetaMcp::handle_tools_list_for_session`). This asserts the disclosed
/// set is exactly what the same fixture's `tools/call` will actually run —
/// for BOTH directions: a hidden tool must refuse, and a disclosed one must
/// not be accidentally refused too.
#[tokio::test]
async fn mik_7332_discovery_1_listed_set_matches_invocable_set() {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(BackendRegistry::new());
    let valid_schema = json!({
        "type": "object",
        "properties": { "q": { "type": "string" } },
        "required": ["q"]
    });
    let _ = registry.register(
        served_surface_backend(
            "alpha",
            vec![
                tool("public_tool", "A publicly surfaced tool.", valid_schema.clone()),
                tool(
                    "denied_tool",
                    "A tool the default profile denies.",
                    valid_schema,
                ),
            ],
            Arc::clone(&calls),
        )
        .await,
    );

    let mut profiles: HashMap<String, RoutingProfileConfig> = HashMap::new();
    profiles.insert(
        "restricted".to_string(),
        RoutingProfileConfig {
            description: "Denies denied_tool".to_string(),
            deny_tools: Some(vec!["denied_tool".to_string()]),
            ..Default::default()
        },
    );
    let profile_registry = ProfileRegistry::from_config(&profiles, "restricted");

    let meta = MetaMcp::new(Arc::clone(&registry))
        .with_profile_registry(profile_registry)
        .with_surfaced_tools(vec![
            SurfacedToolConfig {
                server: "alpha".to_string(),
                tool: "public_tool".to_string(),
            },
            SurfacedToolConfig {
                server: "alpha".to_string(),
                tool: "denied_tool".to_string(),
            },
        ])
        .with_exposed_meta_tools(&[
            "gateway_invoke".to_string(),
            "gateway_search_tools".to_string(),
        ]);

    // --- Disclosure: tools/list ---
    let listed = meta.handle_tools_list_for_session(RequestId::Number(1), None);
    let tools = listed
        .result
        .expect("tools/list must return a result")
        .get("tools")
        .cloned()
        .expect("result must have a tools array");
    let tools = tools.as_array().expect("tools must be an array");
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .collect();

    assert!(
        names.contains(&"public_tool"),
        "the allowed surfaced tool must be listed: {names:?}"
    );
    assert!(
        !names.contains(&"denied_tool"),
        "the profile-denied surfaced tool must NOT be listed: {names:?}"
    );
    assert!(
        names.contains(&"gateway_invoke") && names.contains(&"gateway_search_tools"),
        "exposed meta-tools must be listed: {names:?}"
    );
    assert!(
        !names.contains(&"gateway_list_servers"),
        "a meta-tool outside the exposure allow-list must NOT be listed: {names:?}"
    );

    // --- Schema validity, on the SAME response ---
    let public_entry = tools
        .iter()
        .find(|t| t.get("name").and_then(Value::as_str) == Some("public_tool"))
        .expect("public_tool must be in the listing");
    let input_schema = public_entry
        .get("inputSchema")
        .expect("published tool must carry inputSchema");
    if let Err(err) = jsonschema::meta::validate(input_schema) {
        panic!("public_tool's published inputSchema is not valid JSON Schema 2020-12: {err}");
    }
    assert!(
        public_entry
            .get("trustCard")
            .and_then(|tc| tc.get("schemaBounds"))
            .is_some(),
        "a backend-forwarded descriptor must carry the schema-bounds verdict beside it: {public_entry:?}"
    );

    // --- Invocation permission: the hidden meta-tool must refuse exactly
    // like an unrecognised name, and the surfaced-but-denied tool must
    // refuse without ever reaching the backend. ---
    let hidden_meta = meta
        .handle_tools_call(
            RequestId::Number(2),
            "gateway_list_servers",
            json!({}),
            None,
            ctx(&AllowAll),
        )
        .await;
    let hidden_err = hidden_meta.error.expect("a hidden meta-tool must refuse");
    assert_eq!(hidden_err.code, -32601);
    assert!(
        hidden_err.message.ends_with("Unknown tool: gateway_list_servers"),
        "{}",
        hidden_err.message
    );

    let unrecognised = meta
        .handle_tools_call(
            RequestId::Number(3),
            "gateway_zzz_nonexistent",
            json!({}),
            None,
            ctx(&AllowAll),
        )
        .await;
    let un_err = unrecognised.error.expect("a nonexistent tool must refuse");
    assert_eq!(
        un_err.code, hidden_err.code,
        "a hidden tool and a genuinely nonexistent one must refuse identically"
    );
    assert!(
        un_err.message.ends_with("Unknown tool: gateway_zzz_nonexistent"),
        "{}",
        un_err.message
    );

    let denied_call = meta
        .handle_tools_call(
            RequestId::Number(4),
            "denied_tool",
            json!({"q": "x"}),
            None,
            ctx(&AllowAll),
        )
        .await;
    assert!(
        denied_call.error.is_some(),
        "a tool hidden from discovery by the routing profile must not be invocable directly: {denied_call:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the denied call must never reach the backend"
    );

    let allowed_call = meta
        .handle_tools_call(
            RequestId::Number(5),
            "public_tool",
            json!({"q": "x"}),
            None,
            ctx(&AllowAll),
        )
        .await;
    assert!(
        allowed_call.error.is_none(),
        "the listed, allowed surfaced tool must actually run: {allowed_call:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "and must reach the backend exactly once"
    );
}

/// Code Mode surface: `gateway_search`'s tiered disclosure (L0 drops
/// disabled/killed tools; a profile-denied tool is invisible at every tier
/// because it never becomes a match at all) composes with authorization in
/// `code_mode_search`/`collect_code_mode_backend_matches`. This asserts the
/// disclosure difference is not cosmetic: a killed tool refuses
/// `gateway_execute` regardless of the tier that revealed it, a
/// profile-denied one refuses too, and the plain visible one actually runs.
#[tokio::test]
async fn mik_7332_discovery_1_disclosure_tiers_agree_with_invocation() {
    let registry = Arc::new(BackendRegistry::new());
    let schema = json!({"type": "object", "properties": {}});
    // `alpha` must actually answer `tools/call` — its invocation is expected
    // to succeed, unlike `beta`/`gamma` below, which are refused before
    // dispatch ever reaches their (list-only) transport.
    let _ = registry.register(
        served_surface_backend(
            "alpha",
            vec![tool("alpha_tool", "Alive backend tool. [keywords: widget]", schema.clone())],
            Arc::new(AtomicUsize::new(0)),
        )
        .await,
    );
    let _ = registry.register(
        backend_with_tools(
            "beta",
            vec![tool("beta_tool", "Killed backend tool. [keywords: widget]", schema.clone())],
        )
        .await,
    );
    let _ = registry.register(
        backend_with_tools(
            "gamma",
            vec![tool("gamma_tool", "Profile-denied tool. [keywords: widget]", schema)],
        )
        .await,
    );

    let mut profiles: HashMap<String, RoutingProfileConfig> = HashMap::new();
    profiles.insert(
        "default".to_string(),
        RoutingProfileConfig {
            description: "Denies gamma_tool".to_string(),
            deny_tools: Some(vec!["gamma_tool".to_string()]),
            ..Default::default()
        },
    );
    let profile_registry = ProfileRegistry::from_config(&profiles, "default");

    let meta = MetaMcp::with_features(
        Arc::clone(&registry),
        None,
        None,
        Some(Arc::new(SearchRanker::new())),
        Duration::from_secs(60),
    )
    .with_profile_registry(profile_registry);
    meta.kill_switch().kill("beta");

    // --- L0: killed AND denied tools are both absent, for different reasons.
    let l0 = meta
        .code_mode_search(&json!({ "query": "*_tool", "limit": 10 }), None)
        .await
        .unwrap();
    let l0_names: Vec<&str> = l0["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["tool"].as_str())
        .collect();
    assert!(
        l0_names.iter().any(|n| n.contains("alpha_tool")),
        "the alive, allowed tool must appear at L0: {l0_names:?}"
    );
    assert!(
        !l0_names.iter().any(|n| n.contains("beta_tool")),
        "a killed tool must be dropped at L0: {l0_names:?}"
    );
    assert!(
        !l0_names.iter().any(|n| n.contains("gamma_tool")),
        "a profile-denied tool must never appear, even at L0: {l0_names:?}"
    );

    // --- L1: the killed tool reappears (with its disabled status); the
    // profile-denied one still does not — proving the two absences are
    // different mechanisms, not the same filter under two names.
    let l1 = meta
        .code_mode_search(&json!({ "query": "*_tool", "limit": 10, "detail": "l1" }), None)
        .await
        .unwrap();
    let l1_matches = l1["matches"].as_array().unwrap();
    let beta_at_l1 = l1_matches
        .iter()
        .find(|m| m["tool"].as_str().is_some_and(|n| n.contains("beta_tool")));
    assert!(
        beta_at_l1.is_some(),
        "a killed (not denied) tool must be visible at L1: {l1_matches:?}"
    );
    assert_eq!(
        beta_at_l1.unwrap().get("status").and_then(Value::as_str),
        Some("disabled"),
        "and must carry the disabled status: {beta_at_l1:?}"
    );
    assert!(
        !l1_matches
            .iter()
            .any(|m| m["tool"].as_str().is_some_and(|n| n.contains("gamma_tool"))),
        "the profile-denied tool must still be absent at L1: {l1_matches:?}"
    );

    // --- Invocation: agrees with disclosure in both directions.
    let beta_call = meta
        .code_mode_execute(
            &json!({ "tool": "beta:beta_tool", "arguments": {} }),
            None,
            &ctx(&AllowAll),
        )
        .await;
    assert!(
        beta_call.is_err(),
        "a killed tool must refuse gateway_execute even though L1 disclosed it: {beta_call:?}"
    );

    let gamma_call = meta
        .code_mode_execute(
            &json!({ "tool": "gamma:gamma_tool", "arguments": {} }),
            None,
            &ctx(&AllowAll),
        )
        .await;
    assert!(
        gamma_call.is_err(),
        "a profile-denied tool must refuse gateway_execute: {gamma_call:?}"
    );

    let alpha_call = meta
        .code_mode_execute(
            &json!({ "tool": "alpha:alpha_tool", "arguments": {} }),
            None,
            &ctx(&AllowAll),
        )
        .await;
    assert!(
        alpha_call.is_ok(),
        "the tool visible at L0 must actually run: {alpha_call:?}"
    );
}
