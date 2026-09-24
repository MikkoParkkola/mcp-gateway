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
use crate::gateway::router::CallerStanding;
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
        .code_mode_search_anon(&json!({ "query": "linear create issue", "limit": 2 }), None)
        .await
        .unwrap();
    let shown = meta
        .code_mode_search_anon(
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
        .code_mode_search_anon(&json!({ "query": "linear create issue", "limit": 1 }), None)
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
        .code_mode_search_anon(
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
        .code_mode_search_anon(
            &json!({ "query": "linear create issue", "limit": 1, "include_schema": true }),
            None,
        )
        .await
        .unwrap();
    assert!(via_legacy["matches"][0].get("input_schema").is_some());

    let l2 = meta
        .code_mode_search_anon(
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
            .code_mode_search_anon(&json!({ "query": query, "limit": 3 }), None)
            .await
            .unwrap();
        let legacy = meta
            .code_mode_search_anon(
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
        .code_mode_search_anon(&json!({ "query": "linear", "detail": "full" }), None)
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

async fn served_surface_backend(
    name: &str,
    tools: Vec<Tool>,
    calls: Arc<AtomicUsize>,
) -> Arc<Backend> {
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
#[allow(clippy::too_many_lines)] // one end-to-end trace; splitting it would hide the sequence
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
                tool(
                    "public_tool",
                    "A publicly surfaced tool.",
                    valid_schema.clone(),
                ),
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
    let listed =
        meta.handle_tools_list_for_session(RequestId::Number(1), None, CallerStanding::Admin);
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
    let hidden_meta = Box::pin(meta.handle_tools_call(
        RequestId::Number(2),
        "gateway_list_servers",
        json!({}),
        None,
        ctx(&AllowAll),
    ))
    .await;
    let hidden_err = hidden_meta.error.expect("a hidden meta-tool must refuse");
    assert_eq!(hidden_err.code, -32601);
    assert!(
        hidden_err
            .message
            .ends_with("Unknown tool: gateway_list_servers"),
        "{}",
        hidden_err.message
    );

    let unrecognised = Box::pin(meta.handle_tools_call(
        RequestId::Number(3),
        "gateway_zzz_nonexistent",
        json!({}),
        None,
        ctx(&AllowAll),
    ))
    .await;
    let un_err = unrecognised.error.expect("a nonexistent tool must refuse");
    assert_eq!(
        un_err.code, hidden_err.code,
        "a hidden tool and a genuinely nonexistent one must refuse identically"
    );
    assert!(
        un_err
            .message
            .ends_with("Unknown tool: gateway_zzz_nonexistent"),
        "{}",
        un_err.message
    );

    let denied_call = Box::pin(meta.handle_tools_call(
        RequestId::Number(4),
        "denied_tool",
        json!({"q": "x"}),
        None,
        ctx(&AllowAll),
    ))
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

    let allowed_call = Box::pin(meta.handle_tools_call(
        RequestId::Number(5),
        "public_tool",
        json!({"q": "x"}),
        None,
        ctx(&AllowAll),
    ))
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
#[allow(clippy::too_many_lines)] // one end-to-end trace; splitting it would hide the sequence
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
            vec![tool(
                "alpha_tool",
                "Alive backend tool. [keywords: widget]",
                schema.clone(),
            )],
            Arc::new(AtomicUsize::new(0)),
        )
        .await,
    );
    let _ = registry.register(
        backend_with_tools(
            "beta",
            vec![tool(
                "beta_tool",
                "Killed backend tool. [keywords: widget]",
                schema.clone(),
            )],
        )
        .await,
    );
    let _ = registry.register(
        backend_with_tools(
            "gamma",
            vec![tool(
                "gamma_tool",
                "Profile-denied tool. [keywords: widget]",
                schema,
            )],
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
        .code_mode_search_anon(&json!({ "query": "*_tool", "limit": 10 }), None)
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
        .code_mode_search_anon(
            &json!({ "query": "*_tool", "limit": 10, "detail": "l1" }),
            None,
        )
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

/// Names disclosed by a `tools/list` response, in order.
fn listed_names(response: &JsonRpcResponse) -> Vec<String> {
    response
        .result
        .as_ref()
        .and_then(|r| r.get("tools"))
        .and_then(Value::as_array)
        .expect("tools/list must return a tools array")
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

/// The same caller context as [`ctx`], holding admin.
fn admin_ctx(
    authorizer: &(dyn crate::gateway::authz::ToolAuthorizer + Sync),
) -> crate::gateway::meta_mcp::MetaMcpCallerContext<'_> {
    crate::gateway::meta_mcp::MetaMcpCallerContext {
        is_admin: true,
        ..ctx(authorizer)
    }
}

/// Acceptance clause A (admin/nonadmin axis). Disclosure and dispatch answer
/// the admin question from one predicate, `CallerStanding::permits`
/// (`router::authorization`), so the served list and the invocable set agree on
/// both sides of the axis: a standard caller is neither shown nor served
/// `gateway_kill_server`, an admin is shown it and may run it.
///
/// The control is the second listing. Asserting only that the standard caller
/// is missing the tool would pass for a build that lists nothing at all, or
/// for a `permits` that answers `false` to every name; the admin listing of the
/// same `MetaMcp`, with the same allow-list, is what makes standing the only
/// thing that differs.
#[tokio::test]
async fn mik_7332_discovery_1_admin_axis_disclosure_versus_invocation() {
    let registry = Arc::new(BackendRegistry::new());
    let meta = MetaMcp::new(Arc::clone(&registry)).with_exposed_meta_tools(&[
        "gateway_invoke".to_string(),
        "gateway_kill_server".to_string(),
    ]);

    let standard = listed_names(&meta.handle_tools_list_for_session(
        RequestId::Number(1),
        None,
        CallerStanding::Standard,
    ));
    assert!(
        !standard.contains(&"gateway_kill_server".to_string()),
        "a standard caller must not be shown the admin-only meta-tool: {standard:?}"
    );
    assert!(
        standard.contains(&"gateway_invoke".to_string()),
        "the standing filter must remove the admin tool and nothing else: {standard:?}"
    );

    let admin = listed_names(&meta.handle_tools_list_for_session(
        RequestId::Number(2),
        None,
        CallerStanding::Admin,
    ));
    assert!(
        admin.contains(&"gateway_kill_server".to_string()),
        "the same allow-list must disclose the admin tool to an admin: {admin:?}"
    );

    // The invocation half of the same axis, unchanged by the filter: the
    // refusal a standard caller meets is still the admin gate's, worded as it
    // always was. Dispatch is the authority the listing is derived from, so
    // this is what the two assertions above are agreeing *with*.
    let nonadmin_call = Box::pin(meta.handle_tools_call(
        RequestId::Number(3),
        "gateway_kill_server",
        json!({"server": "alpha"}),
        None,
        ctx(&AllowAll),
    ))
    .await;
    let err = nonadmin_call
        .error
        .expect("a nonadmin must be refused an admin meta-tool");
    assert_eq!(err.code, -32600, "{}", err.message);
    assert!(
        err.message.contains("requires admin access"),
        "the refusal must name the admin gate, not a routing failure: {}",
        err.message
    );

    let admin_call = Box::pin(meta.handle_tools_call(
        RequestId::Number(4),
        "gateway_kill_server",
        json!({"server": "alpha"}),
        None,
        admin_ctx(&AllowAll),
    ))
    .await;
    assert!(
        !admin_call
            .error
            .as_ref()
            .is_some_and(|e| e.message.contains("requires admin access")),
        "the same call from an admin must pass the gate: {admin_call:?}"
    );
}

/// Acceptance clause B (configured/unconfigured features). `gateway_get_stats`
/// is gated at disclosure by `meta_mcp.expose_stats_tool` and at invocation by
/// the collector `Option` (`invoke.rs:3206`). "Unconfigured" is a deployment
/// that set neither, "configured" one that set both. This asserts both ends
/// move together for that operator: unconfigured contributes nothing to the
/// served list and refuses, configured appears and runs.
#[tokio::test]
async fn mik_7332_discovery_1_unconfigured_feature_neither_listed_nor_invocable() {
    let exposure = ["gateway_get_stats".to_string()];
    let registry = Arc::new(BackendRegistry::new());

    let unconfigured = MetaMcp::new(Arc::clone(&registry)).with_exposed_meta_tools(&exposure);
    let listed = listed_names(&unconfigured.handle_tools_list_for_session(
        RequestId::Number(1),
        None,
        CallerStanding::Admin,
    ));
    assert!(
        !listed.contains(&"gateway_get_stats".to_string()),
        "an unconfigured feature must contribute nothing to the served list: {listed:?}"
    );
    let refused = Box::pin(unconfigured.handle_tools_call(
        RequestId::Number(2),
        "gateway_get_stats",
        json!({}),
        None,
        ctx(&AllowAll),
    ))
    .await;
    let err = refused
        .error
        .expect("an unconfigured feature's tool must not execute");
    assert!(
        err.message.contains("Statistics not enabled"),
        "{}",
        err.message
    );

    let configured = MetaMcp::with_features(
        Arc::clone(&registry),
        None,
        Some(Arc::new(crate::stats::UsageStats::new())),
        None,
        Duration::from_secs(60),
    )
    .with_exposed_meta_tools(&exposure)
    .with_expose_stats_tool(true);
    let listed = listed_names(&configured.handle_tools_list_for_session(
        RequestId::Number(3),
        None,
        CallerStanding::Admin,
    ));
    assert!(
        listed.contains(&"gateway_get_stats".to_string()),
        "configuring the feature must surface its tool: {listed:?}"
    );
    let ran = Box::pin(configured.handle_tools_call(
        RequestId::Number(4),
        "gateway_get_stats",
        json!({}),
        None,
        ctx(&AllowAll),
    ))
    .await;
    assert!(
        ran.error.is_none(),
        "the surfaced tool must actually execute: {ran:?}"
    );
}

/// Every `gateway_*` name mentioned in a guide's text.
fn guide_tool_names(text: &str) -> std::collections::BTreeSet<String> {
    text.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|word| word.starts_with("gateway_"))
        .map(str::to_string)
        .collect()
}

/// Read the gateway-owned routing guide as the given caller is served it.
async fn routing_guide_text(meta: &MetaMcp, standing: CallerStanding) -> String {
    let uri = json!({"uri": "gateway://guides/routing"});
    let response = meta
        .handle_resources_read(RequestId::Number(1), Some(&uri), standing, None, None)
        .await;
    response
        .result
        .and_then(|r| r.get("contents").and_then(Value::as_array).cloned())
        .and_then(|contents| contents.first().cloned())
        .and_then(|entry| {
            entry
                .get("text")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .expect("the routing guide resource must return text")
}

/// Acceptance clause C (routing guide agreement). The guide served at
/// `gateway://guides/routing` is projected through the same served set
/// `tools/list` answers from, so no caller is ever handed instructions for a
/// tool their own catalogue withholds — on either axis the surface narrows by.
///
/// Three surfaces, because "the guide names nothing" would satisfy a subset
/// assertion on its own. The admin default is the positive control: the guide
/// must still name the kill switch and every name in it must be listed. The
/// standard caller and the allow-listed operator are the two ways the surface
/// shrinks, and each is checked for subset *and* for the specific name that
/// had to disappear.
#[tokio::test]
async fn mik_7332_discovery_1_routing_guide_agrees_with_served_list() {
    let registry = Arc::new(BackendRegistry::new());
    let meta = MetaMcp::new(Arc::clone(&registry));

    // Positive control: the full surface keeps the guide whole.
    let named = guide_tool_names(&routing_guide_text(&meta, CallerStanding::Admin).await);
    assert!(
        named.contains("gateway_kill_server"),
        "an admin's routing guide must still document the kill switch: {named:?}"
    );
    let listed = listed_names(&meta.handle_tools_list_for_session(
        RequestId::Number(2),
        None,
        CallerStanding::Admin,
    ));
    for name in &named {
        assert!(
            listed.contains(name),
            "the routing guide names {name} but the served list withholds it: {listed:?}"
        );
    }

    // Standing axis: the same gateway, a caller without operator rights.
    let standard_named =
        guide_tool_names(&routing_guide_text(&meta, CallerStanding::Standard).await);
    assert!(
        !standard_named.contains("gateway_kill_server"),
        "a standard caller's guide must not document a tool they cannot run: {standard_named:?}"
    );
    assert!(
        !standard_named.is_empty(),
        "the guide must still route the tools this caller does have: {standard_named:?}"
    );
    let standard_listed = listed_names(&meta.handle_tools_list_for_session(
        RequestId::Number(3),
        None,
        CallerStanding::Standard,
    ));
    for name in &standard_named {
        assert!(
            standard_listed.contains(name),
            "the guide names {name} to a caller whose list withholds it: {standard_listed:?}"
        );
    }

    // Exposure axis: an operator allow-list that hides most of the surface.
    let narrowed = MetaMcp::new(Arc::clone(&registry)).with_exposed_meta_tools(&[
        "gateway_invoke".to_string(),
        "gateway_search_tools".to_string(),
    ]);
    let narrowed_named =
        guide_tool_names(&routing_guide_text(&narrowed, CallerStanding::Admin).await);
    let narrowed_listed = listed_names(&narrowed.handle_tools_list_for_session(
        RequestId::Number(4),
        None,
        CallerStanding::Admin,
    ));
    for name in &narrowed_named {
        assert!(
            narrowed_listed.contains(name),
            "the narrowed guide names {name}, which the allow-list withholds: {narrowed_listed:?}"
        );
    }
    let hidden = "gateway_list_profiles";
    assert!(
        !narrowed_named.contains(hidden),
        "the guide must drop the section naming {hidden}: {narrowed_named:?}"
    );
    // And the tool the guide no longer names is genuinely unreachable, so the
    // text was removed because the surface shrank, not merely edited.
    let refused = Box::pin(narrowed.handle_tools_call(
        RequestId::Number(5),
        hidden,
        json!({}),
        None,
        admin_ctx(&AllowAll),
    ))
    .await;
    let err = refused
        .error
        .expect("a tool outside the allow-list must refuse");
    assert_eq!(err.code, -32601, "{}", err.message);
}

/// A capability YAML naming one REST provider, with the given input schema.
fn capability_yaml(name: &str, input_type: &str) -> String {
    format!(
        "name: {name}\n\
         description: A surfaced capability used to prove per-tool degradation.\n\
         schema:\n  \
           input:\n    \
             type: {input_type}\n    \
             properties:\n      \
               q:\n        \
                 type: string\n\
         providers:\n  \
           primary:\n    \
             service: rest\n    \
             config:\n      \
               base_url: https://rest.invalid\n      \
               path: /{name}\n"
    )
}

/// Acceptance clause D (invalid schema withheld, healthy tools remain). A
/// capability whose `schema.input.type` is not `object` fails structural
/// validation with a CAP-003 error, and the loader skips that definition alone
/// (`capability/loader.rs:146`). This asserts the degradation is per-tool: the
/// broken tool is absent from the capability backend, absent from the served
/// `tools/list`, and refuses invocation, while its schema-valid sibling on the
/// same backend stays listed and routable. The sibling's execution stops at
/// routing — running it would issue the REST call its provider declares.
#[tokio::test]
async fn mik_7332_discovery_1_invalid_schema_tool_withheld_backend_survives() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("healthy.yaml"),
        capability_yaml("healthy_cap", "object"),
    )
    .expect("write healthy capability");
    std::fs::write(
        dir.path().join("broken.yaml"),
        capability_yaml("broken_cap", "string"),
    )
    .expect("write broken capability");

    let capabilities = Arc::new(crate::capability::CapabilityBackend::new(
        "caps",
        Arc::new(crate::capability::CapabilityExecutor::new()),
    ));
    let loaded = capabilities
        .load_from_directory(dir.path().to_str().expect("utf-8 path"))
        .await
        .expect("a backend with one invalid definition must still load");
    assert_eq!(
        loaded, 1,
        "only the schema-valid capability may load; the backend must not be dropped whole"
    );
    assert!(capabilities.has_capability("healthy_cap"));
    assert!(
        !capabilities.has_capability("broken_cap"),
        "the invalid-schema capability must be withheld"
    );

    // Control: the same definition, with only `schema.input.type` corrected,
    // loads. Without it this test would pass for any load failure at all.
    let control_dir = tempfile::TempDir::new().expect("temp dir");
    std::fs::write(
        control_dir.path().join("broken.yaml"),
        capability_yaml("broken_cap", "object"),
    )
    .expect("write control capability");
    let control = Arc::new(crate::capability::CapabilityBackend::new(
        "caps",
        Arc::new(crate::capability::CapabilityExecutor::new()),
    ));
    assert_eq!(
        control
            .load_from_directory(control_dir.path().to_str().expect("utf-8 path"))
            .await
            .expect("the control definition must load"),
        1,
        "only the input schema may decide whether this definition loads"
    );

    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_surfaced_tools(vec![
            SurfacedToolConfig {
                server: "caps".to_string(),
                tool: "healthy_cap".to_string(),
            },
            SurfacedToolConfig {
                server: "caps".to_string(),
                tool: "broken_cap".to_string(),
            },
        ])
        .with_exposed_meta_tools(&["gateway_invoke".to_string()]);
    meta.set_capabilities(Arc::clone(&capabilities));

    let listed = listed_names(&meta.handle_tools_list_for_session(
        RequestId::Number(1),
        None,
        CallerStanding::Admin,
    ));
    assert!(
        listed.contains(&"healthy_cap".to_string()),
        "the healthy tool of the same backend must remain listed: {listed:?}"
    );
    assert!(
        !listed.contains(&"broken_cap".to_string()),
        "the invalid-schema tool must not be disclosed: {listed:?}"
    );

    assert!(
        capabilities
            .call_tool("broken_cap", json!({"q": "x"}))
            .await
            .is_err(),
        "the withheld tool must not be invocable either"
    );
}

/// Acceptance clause D, MCP-backend half. A capability is validated as it is
/// read off disk, so a malformed `schema.input` never reaches the surface. A
/// backend's tools arrive over the wire instead, and until this test the
/// gateway surfaced whatever a backend sent: a tool whose `inputSchema` is not
/// an object is a tool no client can build a call against, disclosed anyway.
///
/// Same verdict, same degradation shape as the capability path above: the one
/// bad tool is withheld from `tools/list` and refused by name, its healthy
/// sibling on the same backend stays listed and still routes, and the backend
/// itself is not dropped. The healthy control is what separates "the schema
/// decided this" from "the backend fell over".
#[tokio::test]
async fn mik_7332_discovery_1_invalid_schema_backend_tool_withheld_siblings_survive() {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = served_surface_backend(
        "wire",
        vec![
            tool(
                "healthy_wire",
                "A backend tool whose input schema is a proper object.",
                json!({"type": "object", "properties": {"q": {"type": "string"}}}),
            ),
            // `type: string` is the same CAP-003 error the capability loader
            // refuses a definition for.
            tool(
                "broken_wire",
                "A backend tool whose input schema is not an object.",
                json!({"type": "string", "properties": {"q": {"type": "string"}}}),
            ),
        ],
        Arc::clone(&calls),
    )
    .await;

    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(Arc::clone(&backend));
    let meta = MetaMcp::new(Arc::clone(&registry))
        .with_surfaced_tools(vec![
            SurfacedToolConfig {
                server: "wire".to_string(),
                tool: "healthy_wire".to_string(),
            },
            SurfacedToolConfig {
                server: "wire".to_string(),
                tool: "broken_wire".to_string(),
            },
        ])
        .with_exposed_meta_tools(&["gateway_invoke".to_string()]);

    let listed = listed_names(&meta.handle_tools_list_for_session(
        RequestId::Number(1),
        None,
        CallerStanding::Admin,
    ));
    assert!(
        listed.contains(&"healthy_wire".to_string()),
        "the healthy tool of the same backend must remain listed: {listed:?}"
    );
    assert!(
        !listed.contains(&"broken_wire".to_string()),
        "a structurally invalid input schema must not be disclosed: {listed:?}"
    );
    assert!(
        backend.has_cached_tools(),
        "one bad tool must not take the backend down with it"
    );

    // Unlisted and uninvocable are the same claim read two ways. The refusal
    // is worded like the unrecognised-tool fallback so it does not confirm the
    // existence of a tool the gateway declined to publish, and the backend
    // must never have been reached.
    let refused = Box::pin(meta.handle_tools_call(
        RequestId::Number(2),
        "broken_wire",
        json!({"q": "x"}),
        None,
        ctx(&AllowAll),
    ))
    .await;
    let err = refused
        .error
        .expect("a tool withheld from the catalogue must not execute");
    assert_eq!(err.code, -32601, "{}", err.message);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the refusal must land before the backend is asked"
    );

    let ran = Box::pin(meta.handle_tools_call(
        RequestId::Number(3),
        "healthy_wire",
        json!({"q": "x"}),
        None,
        ctx(&AllowAll),
    ))
    .await;
    assert!(
        ran.error.is_none(),
        "the sibling must still route through the same path: {ran:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the healthy sibling must reach the backend"
    );
}
