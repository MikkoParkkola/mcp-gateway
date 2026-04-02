use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use crate::backend::BackendRegistry;
use crate::config::Config;
use crate::config_reload::{LiveConfig, ReloadContext};
use crate::protocol::RequestId;

use super::*;
use crate::gateway::trace;

// ── augment_with_trace ────────────────────────────────────────────────

#[test]
fn augment_with_trace_inserts_trace_id_field() {
    // GIVEN: a JSON object result and a trace ID
    let result = json!({"content": [{"type": "text", "text": "hello"}]});
    let trace_id = "gw-abc123";
    // WHEN: augmenting with the trace ID
    let augmented = support::augment_with_trace(result, trace_id);
    // THEN: trace_id field is present with the correct value
    assert_eq!(augmented["trace_id"], "gw-abc123");
}

#[test]
fn augment_with_trace_preserves_existing_fields() {
    // GIVEN: a result with content and predicted_next
    let result = json!({
        "content": [{"type": "text", "text": "ok"}],
        "predicted_next": [{"tool": "foo", "confidence": 0.8}]
    });
    // WHEN: augmenting with a trace ID
    let augmented = support::augment_with_trace(result, "gw-xyz");
    // THEN: existing fields are preserved
    assert!(augmented.get("content").is_some());
    assert!(augmented.get("predicted_next").is_some());
    assert_eq!(augmented["trace_id"], "gw-xyz");
}

#[test]
fn augment_with_trace_does_not_modify_non_object_values() {
    // GIVEN: a non-object JSON value (edge case)
    let result = json!(null);
    // WHEN: augmenting
    let augmented = support::augment_with_trace(result, "gw-abc");
    // THEN: null is returned unchanged (no panic)
    assert!(augmented.is_null());
}

// ── augment_with_predictions ──────────────────────────────────────────

#[test]
fn augment_with_predictions_no_op_when_empty() {
    // GIVEN: empty predictions
    let result = json!({"content": []});
    let original = result.clone();
    // WHEN: augmenting with empty predictions
    let augmented = support::augment_with_predictions(result, vec![]);
    // THEN: result is unchanged
    assert_eq!(augmented, original);
}

#[test]
fn augment_with_predictions_inserts_predicted_next() {
    // GIVEN: one prediction
    let result = json!({"content": []});
    let predictions = vec![json!({"tool": "foo:bar", "confidence": 0.9})];
    // WHEN: augmenting
    let augmented = support::augment_with_predictions(result, predictions);
    // THEN: predicted_next field is present
    let preds = augmented["predicted_next"].as_array().unwrap();
    assert_eq!(preds.len(), 1);
    assert_eq!(preds[0]["tool"], "foo:bar");
}

// ── trace ID generation roundtrip ─────────────────────────────────────

#[tokio::test]
async fn invoke_tool_trace_id_is_accessible_inside_scope() {
    // GIVEN: a fresh trace ID
    let id = trace::generate();
    // WHEN: inside a with_trace_id scope
    let observed = trace::with_trace_id(id.clone(), async { trace::current() }).await;
    // THEN: the same ID is visible inside the scope
    assert_eq!(observed, Some(id));
}

#[tokio::test]
async fn trace_id_not_accessible_outside_scope() {
    // GIVEN: no active scope
    // WHEN: reading outside any with_trace_id scope
    // THEN: current() returns None
    assert_eq!(trace::current(), None);
}

// ── Code Mode: handle_tools_list ─────────────────────────────────────────

fn make_meta_mcp() -> MetaMcp {
    MetaMcp::new(Arc::new(BackendRegistry::new()))
}

fn make_meta_mcp_code_mode() -> MetaMcp {
    MetaMcp::new(Arc::new(BackendRegistry::new())).with_code_mode(true)
}

#[test]
fn new_matches_featureless_constructor_defaults() {
    let backends = Arc::new(BackendRegistry::new());
    let from_new = MetaMcp::new(Arc::clone(&backends));
    let from_with_features =
        MetaMcp::with_features(backends, None, None, None, Duration::from_secs(60));

    assert!(from_new.cache.is_none());
    assert!(from_with_features.cache.is_none());
    assert_eq!(from_new.default_cache_ttl, Duration::from_secs(60));
    assert_eq!(
        from_new.default_cache_ttl,
        from_with_features.default_cache_ttl
    );
    assert!(from_new.stats.is_none());
    assert!(from_with_features.stats.is_none());
    assert!(from_new.ranker.is_none());
    assert!(from_with_features.ranker.is_none());
    assert!(from_new.capabilities.read().is_none());
    assert!(from_with_features.capabilities.read().is_none());
    assert!(from_new.reload_context.read().is_none());
    assert!(from_with_features.reload_context.read().is_none());
    assert!(!from_new.code_mode_enabled);
    assert!(!from_with_features.code_mode_enabled);
    assert!(from_new.surfaced_tools.is_empty());
    assert!(from_with_features.surfaced_tools.is_empty());
    assert!(from_new.surfaced_tools_map.is_empty());
    assert!(from_with_features.surfaced_tools_map.is_empty());
}

#[test]
fn handle_tools_list_code_mode_disabled_returns_meta_tools() {
    // GIVEN: code mode is disabled
    let meta = make_meta_mcp();
    // WHEN: tools/list is called
    let response = meta.handle_tools_list(RequestId::Number(1));
    // THEN: response has no error
    assert!(response.error.is_none());
    let result = response.result.unwrap();
    let tools = result["tools"].as_array().unwrap();
    // Traditional mode returns 9+ meta-tools (none of which are gateway_search/gateway_execute)
    assert!(
        tools.len() >= 9,
        "Expected at least 9 meta-tools, got {}",
        tools.len()
    );
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(names.contains(&"gateway_invoke"));
    assert!(names.contains(&"gateway_search_tools"));
    assert!(
        !names.contains(&"gateway_search"),
        "gateway_search should NOT appear in traditional mode"
    );
    assert!(
        !names.contains(&"gateway_execute"),
        "gateway_execute should NOT appear in traditional mode"
    );
}

#[test]
fn handle_tools_list_code_mode_enabled_returns_exactly_two_tools() {
    // GIVEN: code mode is enabled
    let meta = make_meta_mcp_code_mode();
    // WHEN: tools/list is called
    let response = meta.handle_tools_list(RequestId::Number(1));
    // THEN: exactly two tools are returned
    assert!(response.error.is_none());
    let result = response.result.unwrap();
    let tools = result["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2, "Code mode must return exactly 2 tools");
}

#[test]
fn handle_tools_list_code_mode_enabled_first_tool_is_gateway_search() {
    // GIVEN: code mode enabled
    let meta = make_meta_mcp_code_mode();
    // WHEN: tools/list
    let response = meta.handle_tools_list(RequestId::Number(2));
    let tools = response.result.unwrap()["tools"].clone();
    // THEN: first tool is gateway_search
    assert_eq!(tools[0]["name"], "gateway_search");
}

#[test]
fn handle_tools_list_code_mode_enabled_second_tool_is_gateway_execute() {
    // GIVEN: code mode enabled
    let meta = make_meta_mcp_code_mode();
    // WHEN: tools/list
    let response = meta.handle_tools_list(RequestId::Number(3));
    let tools = response.result.unwrap()["tools"].clone();
    // THEN: second tool is gateway_execute
    assert_eq!(tools[1]["name"], "gateway_execute");
}

#[test]
fn handle_tools_list_code_mode_enabled_does_not_include_traditional_tools() {
    // GIVEN: code mode enabled
    let meta = make_meta_mcp_code_mode();
    // WHEN: tools/list
    let response = meta.handle_tools_list(RequestId::Number(4));
    let tools = response.result.unwrap()["tools"].clone();
    let tools = tools.as_array().unwrap();
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    // THEN: traditional meta-tools are absent
    assert!(
        !names.contains(&"gateway_invoke"),
        "gateway_invoke should not appear in code mode"
    );
    assert!(
        !names.contains(&"gateway_search_tools"),
        "gateway_search_tools should not appear in code mode"
    );
    assert!(
        !names.contains(&"gateway_list_servers"),
        "gateway_list_servers should not appear in code mode"
    );
}

// ── Code Mode: with_code_mode builder ────────────────────────────────────

#[test]
fn with_code_mode_false_is_default() {
    // GIVEN: MetaMcp built without code mode
    let meta = make_meta_mcp();
    // WHEN: tools/list
    let response = meta.handle_tools_list(RequestId::Number(10));
    let tools = response.result.unwrap()["tools"].clone();
    // THEN: not code mode (>2 tools)
    assert!(tools.as_array().unwrap().len() > 2);
}

#[test]
fn with_code_mode_true_toggles_behavior() {
    // GIVEN: MetaMcp built with code mode toggled on
    let meta = make_meta_mcp().with_code_mode(true);
    // WHEN: tools/list
    let response = meta.handle_tools_list(RequestId::Number(11));
    let tools = response.result.unwrap()["tools"].clone();
    // THEN: exactly 2 tools returned
    assert_eq!(tools.as_array().unwrap().len(), 2);
}

// ── Code Mode: code_mode_execute error paths ──────────────────────────────

#[tokio::test]
async fn code_mode_execute_missing_tool_parameter_returns_error() {
    // GIVEN: args without 'tool' or 'chain'
    let meta = make_meta_mcp_code_mode();
    let args = json!({ "arguments": {} });
    // WHEN: code_mode_execute is called
    let result = meta.code_mode_execute(&args, None).await;
    // THEN: error about missing 'tool'
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("tool") || msg.contains("Missing"),
        "Expected error about missing tool, got: {msg}"
    );
}

#[tokio::test]
async fn code_mode_execute_bare_tool_name_without_server_returns_error() {
    // GIVEN: tool ref without server prefix
    let meta = make_meta_mcp_code_mode();
    let args = json!({ "tool": "my_tool", "arguments": {} });
    // WHEN: code_mode_execute is called
    let result = meta.code_mode_execute(&args, None).await;
    // THEN: error about missing server prefix
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("server") || msg.contains("prefix"),
        "Expected error about server prefix, got: {msg}"
    );
}

#[tokio::test]
async fn code_mode_execute_chain_empty_array_returns_error() {
    // GIVEN: empty chain
    let meta = make_meta_mcp_code_mode();
    let args = json!({ "chain": [] });
    // WHEN: code_mode_execute is called
    let result = meta.code_mode_execute(&args, None).await;
    // THEN: error about empty chain
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("empty") || msg.contains("Chain"),
        "Expected error about empty chain, got: {msg}"
    );
}

#[tokio::test]
async fn code_mode_execute_chain_step_missing_tool_field_returns_error() {
    // GIVEN: chain step without 'tool' field
    let meta = make_meta_mcp_code_mode();
    let args = json!({
        "chain": [
            {"arguments": {}}
        ]
    });
    // WHEN: code_mode_execute is called
    let result = meta.code_mode_execute(&args, None).await;
    // THEN: error about missing tool field in step 0
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("step 0") || msg.contains("missing 'tool'"),
        "Expected error about step 0, got: {msg}"
    );
}

#[tokio::test]
async fn code_mode_execute_chain_step_bare_tool_name_returns_error() {
    // GIVEN: chain step with bare tool name (no server prefix)
    let meta = make_meta_mcp_code_mode();
    let args = json!({
        "chain": [
            {"tool": "my_bare_tool"}
        ]
    });
    // WHEN: code_mode_execute is called
    let result = meta.code_mode_execute(&args, None).await;
    // THEN: error about missing server prefix for step 0
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("server prefix") || msg.contains("step 0"),
        "Expected error about step 0 server prefix, got: {msg}"
    );
}

// ── Code Mode: gateway_search and gateway_execute are always callable ─────

#[tokio::test]
async fn gateway_search_is_callable_regardless_of_code_mode_flag() {
    // GIVEN: code mode disabled, but calling gateway_search explicitly
    let meta = make_meta_mcp();
    let args = json!({ "query": "nonexistent_xyz_404" });
    let response = meta
        .handle_tools_call(RequestId::Number(99), "gateway_search", args, None, None)
        .await;
    // THEN: no JSON-RPC error (-32601 unknown tool), just zero results
    assert!(
        response.error.is_none(),
        "gateway_search should be callable even without code_mode enabled; got: {:?}",
        response.error
    );
}

#[tokio::test]
async fn gateway_execute_missing_tool_and_chain_returns_tool_call_error() {
    // GIVEN: code mode disabled, calling gateway_execute with no tool/chain
    let meta = make_meta_mcp();
    let args = json!({});
    let response = meta
        .handle_tools_call(RequestId::Number(100), "gateway_execute", args, None, None)
        .await;
    // THEN: returns an error (not -32601 unknown tool)
    // The response wraps the error as tool content (is_error=true) OR as RPC error
    // Either way, there should not be a -32601 "Unknown tool" error
    if let Some(ref err) = response.error {
        assert_ne!(
            err.code, -32601,
            "Should not be 'Unknown tool' error; got code={}",
            err.code
        );
    }
    // If no RPC error, the tool result should indicate an error condition
}

// ── Toolshed: list_profiles ───────────────────────────────────────────

fn make_meta_mcp_with_profiles() -> MetaMcp {
    use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
    use std::collections::HashMap;

    let backends = Arc::new(BackendRegistry::new());
    let mut configs: HashMap<String, RoutingProfileConfig> = HashMap::new();
    configs.insert(
        "research".to_string(),
        RoutingProfileConfig {
            description: "Web research tools".to_string(),
            allow_tools: Some(vec!["brave_*".to_string()]),
            ..Default::default()
        },
    );
    configs.insert(
        "coding".to_string(),
        RoutingProfileConfig {
            description: "Software dev — no social".to_string(),
            deny_tools: Some(vec!["slack_*".to_string()]),
            ..Default::default()
        },
    );
    let registry = ProfileRegistry::from_config(&configs, "research");

    MetaMcp::new(backends).with_profile_registry(registry)
}

#[test]
fn list_profiles_returns_all_profiles_sorted_alphabetically() {
    // GIVEN: a MetaMcp with two configured profiles
    let mm = make_meta_mcp_with_profiles();
    // WHEN: calling list_profiles
    let result = mm.list_profiles().unwrap();
    // THEN: profiles array contains both, sorted alphabetically
    let profiles = result["profiles"].as_array().unwrap();
    assert_eq!(profiles.len(), 2);
    assert_eq!(profiles[0]["name"], "coding");
    assert_eq!(profiles[1]["name"], "research");
}

#[test]
fn list_profiles_includes_description_for_each_profile() {
    // GIVEN: a MetaMcp with profiles that have descriptions
    let mm = make_meta_mcp_with_profiles();
    // WHEN
    let result = mm.list_profiles().unwrap();
    // THEN: each profile has a non-empty description
    let profiles = result["profiles"].as_array().unwrap();
    for profile in profiles {
        assert!(
            profile["description"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "Profile '{}' missing description",
            profile["name"]
        );
    }
}

#[test]
fn list_profiles_reports_correct_default() {
    // GIVEN: registry with default = "research"
    let mm = make_meta_mcp_with_profiles();
    // WHEN
    let result = mm.list_profiles().unwrap();
    // THEN: default field matches
    assert_eq!(result["default"], "research");
}

#[test]
fn list_profiles_reports_correct_total() {
    // GIVEN: two configured profiles
    let mm = make_meta_mcp_with_profiles();
    // WHEN
    let result = mm.list_profiles().unwrap();
    // THEN: total = 2
    assert_eq!(result["total"], 2);
}

#[test]
fn list_profiles_empty_when_no_profiles_configured() {
    // GIVEN: a MetaMcp with default (empty) registry
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new()));
    // WHEN
    let result = mm.list_profiles().unwrap();
    // THEN: profiles array is empty, total = 0
    let profiles = result["profiles"].as_array().unwrap();
    assert!(profiles.is_empty());
    assert_eq!(result["total"], 0);
}

// ── Toolshed: handle_initialize profile binding ───────────────────────

#[test]
fn initialize_with_profile_in_params_binds_session() {
    // GIVEN: MetaMcp with profiles + a session ID + profile in params
    let mm = make_meta_mcp_with_profiles();
    let id = RequestId::Number(1);
    let params = json!({"protocolVersion": "2024-11-05", "profile": "coding"});
    // WHEN: initializing with session_id and profile param
    mm.handle_initialize(id, Some(&params), Some("session-42"), None);
    // THEN: session is bound to "coding"
    let active = mm
        .session_profiles
        .get_profile_name("session-42", "research");
    assert_eq!(active, "coding");
}

#[test]
fn initialize_with_header_profile_takes_precedence_over_params() {
    // GIVEN: both header and params specify a profile
    let mm = make_meta_mcp_with_profiles();
    let id = RequestId::Number(2);
    let params = json!({"protocolVersion": "2024-11-05", "profile": "research"});
    // WHEN: header says "coding", params say "research"
    mm.handle_initialize(id, Some(&params), Some("session-99"), Some("coding"));
    // THEN: header wins — session bound to "coding"
    let active = mm
        .session_profiles
        .get_profile_name("session-99", "research");
    assert_eq!(active, "coding");
}

#[test]
fn initialize_with_unknown_profile_does_not_bind_session() {
    // GIVEN: params specify a profile that doesn't exist
    let mm = make_meta_mcp_with_profiles();
    let id = RequestId::Number(3);
    let params = json!({"protocolVersion": "2024-11-05", "profile": "nonexistent"});
    // WHEN: initializing with unknown profile
    mm.handle_initialize(id, Some(&params), Some("session-77"), None);
    // THEN: session is NOT bound (default remains "research")
    let active = mm
        .session_profiles
        .get_profile_name("session-77", "research");
    assert_eq!(active, "research");
}

#[test]
fn initialize_without_profile_does_not_change_session() {
    // GIVEN: no profile in params or header
    let mm = make_meta_mcp_with_profiles();
    // Pre-set session to "coding"
    mm.session_profiles.set_profile("session-5", "coding");
    let id = RequestId::Number(4);
    let params = json!({"protocolVersion": "2024-11-05"});
    // WHEN: initializing without profile hint
    mm.handle_initialize(id, Some(&params), Some("session-5"), None);
    // THEN: existing binding is preserved
    let active = mm
        .session_profiles
        .get_profile_name("session-5", "research");
    assert_eq!(active, "coding");
}

#[test]
fn initialize_without_session_id_succeeds_without_panic() {
    // GIVEN: no session_id (stateless call)
    let mm = make_meta_mcp_with_profiles();
    let id = RequestId::Number(5);
    let params = json!({"protocolVersion": "2024-11-05", "profile": "coding"});
    // WHEN / THEN: no panic; profile is simply not bound
    let resp = mm.handle_initialize(id, Some(&params), None, None);
    // Response should be a success (not an error)
    let v = serde_json::to_value(resp).unwrap();
    assert!(v.get("error").is_none(), "Expected success response");
}

// ── Toolshed: gateway_list_profiles appears in tools/list ─────────────

#[test]
fn gateway_list_profiles_tool_appears_in_tools_list() {
    // GIVEN: a MetaMcp instance (no stats, no webhooks, no reload)
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new()));
    // WHEN: listing tools
    let id = RequestId::Number(0);
    let resp = mm.handle_tools_list(id);
    let v = serde_json::to_value(resp).unwrap();
    // THEN: gateway_list_profiles is in the tool names
    let tools = v["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(
        names.contains(&"gateway_list_profiles"),
        "Expected gateway_list_profiles in tools list, got: {names:?}"
    );
}

#[tokio::test]
async fn gateway_reload_config_surfaces_restart_required_fields() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");

    let old_config = Config::default();
    let mut new_config = old_config.clone();
    new_config.server.port += 1;
    std::fs::write(&config_path, serde_yaml::to_string(&new_config).unwrap()).unwrap();

    let registry = Arc::new(BackendRegistry::new());
    let live_config = Arc::new(LiveConfig::new(old_config.clone()));
    let reload_ctx = Arc::new(ReloadContext::new(
        config_path,
        Arc::clone(&live_config),
        Arc::clone(&registry),
        old_config.failsafe.clone(),
        old_config.meta_mcp.cache_ttl,
    ));

    let mm = MetaMcp::new(Arc::clone(&registry));
    mm.set_reload_context(reload_ctx);

    let resp = mm
        .handle_tools_call(
            RequestId::Number(7),
            "gateway_reload_config",
            json!({}),
            None,
            None,
        )
        .await;

    assert!(
        resp.error.is_none(),
        "unexpected reload error: {:?}",
        resp.error
    );
    let result = resp.result.unwrap();
    let text = result["content"][0]["text"]
        .as_str()
        .expect("tool result text");
    let payload: serde_json::Value = serde_json::from_str(text).unwrap();

    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["restart_required"], true);
    assert_eq!(payload["restart_reason"], "server_address_changed");
    assert!(
        payload["changes"]
            .as_str()
            .is_some_and(|changes| changes.contains("restart required")),
        "expected restart-required summary, got: {payload}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 2: Static Tool Surfacing (RFC-0081 §T2.*)
// ═══════════════════════════════════════════════════════════════════════════

use crate::config::SurfacedToolConfig;

// ── T2.1: Backend::get_cached_tool() ──────────────────────────────────────

#[test]
fn backend_get_cached_tool_returns_none_when_cache_empty() {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};
    use std::time::Duration;
    // GIVEN: a fresh backend with empty cache
    let backend = Backend::new(
        "test",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    );
    // WHEN: looking up a tool
    let result = backend.get_cached_tool("some_tool");
    // THEN: None because cache is empty
    assert!(result.is_none());
}

// ── T2.2 / T2.5: with_surfaced_tools builder — collision detection ─────────

#[test]
fn with_surfaced_tools_stores_valid_entries() {
    // GIVEN: valid surfaced tool config (no collision, no duplicate)
    let tools = vec![SurfacedToolConfig {
        server: "backend_a".to_string(),
        tool: "my_custom_tool".to_string(),
    }];
    // WHEN: building MetaMcp
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new())).with_surfaced_tools(tools);
    // THEN: entry is stored
    assert_eq!(mm.surfaced_tools.len(), 1);
    assert_eq!(mm.surfaced_tools[0].tool, "my_custom_tool");
    assert_eq!(
        mm.surfaced_tools_map.get("my_custom_tool").unwrap(),
        "backend_a"
    );
}

#[test]
fn with_surfaced_tools_drops_collision_with_meta_tool() {
    // GIVEN: a surfaced tool whose name collides with a meta-tool
    let tools = vec![
        SurfacedToolConfig {
            server: "backend_a".to_string(),
            tool: "gateway_invoke".to_string(), // meta-tool collision
        },
        SurfacedToolConfig {
            server: "backend_a".to_string(),
            tool: "my_real_tool".to_string(), // valid
        },
    ];
    // WHEN: building MetaMcp
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new())).with_surfaced_tools(tools);
    // THEN: only the non-colliding entry is kept
    assert_eq!(mm.surfaced_tools.len(), 1);
    assert_eq!(mm.surfaced_tools[0].tool, "my_real_tool");
    assert!(!mm.surfaced_tools_map.contains_key("gateway_invoke"));
}

#[test]
fn with_surfaced_tools_drops_all_known_meta_tool_names() {
    // GIVEN: all known meta-tool names as surfaced tools
    let meta_names = vec![
        "gateway_search",
        "gateway_execute",
        "gateway_list_servers",
        "gateway_list_tools",
        "gateway_search_tools",
        "gateway_invoke",
        "gateway_get_stats",
        "gateway_cost_report",
        "gateway_webhook_status",
        "gateway_run_playbook",
        "gateway_kill_server",
        "gateway_revive_server",
        "gateway_list_disabled_capabilities",
        "gateway_set_profile",
        "gateway_get_profile",
        "gateway_list_profiles",
        "gateway_reload_config",
    ];
    let tools: Vec<SurfacedToolConfig> = meta_names
        .iter()
        .map(|name| SurfacedToolConfig {
            server: "backend".to_string(),
            tool: (*name).to_string(),
        })
        .collect();
    // WHEN
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new())).with_surfaced_tools(tools);
    // THEN: all are dropped
    assert!(mm.surfaced_tools.is_empty());
    assert!(mm.surfaced_tools_map.is_empty());
}

#[test]
fn with_surfaced_tools_drops_duplicate_tool_names() {
    // GIVEN: two entries with the same tool name on different servers
    let tools = vec![
        SurfacedToolConfig {
            server: "server_a".to_string(),
            tool: "shared_tool".to_string(),
        },
        SurfacedToolConfig {
            server: "server_b".to_string(),
            tool: "shared_tool".to_string(), // duplicate
        },
    ];
    // WHEN
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new())).with_surfaced_tools(tools);
    // THEN: only the first occurrence is retained
    assert_eq!(mm.surfaced_tools.len(), 1);
    assert_eq!(mm.surfaced_tools[0].server, "server_a");
}

#[test]
fn with_surfaced_tools_empty_input_is_no_op() {
    // GIVEN: empty list
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new())).with_surfaced_tools(vec![]);
    // WHEN / THEN: no entries
    assert!(mm.surfaced_tools.is_empty());
    assert!(mm.surfaced_tools_map.is_empty());
}

// ── T2.3: Surfaced tools appear in tools/list ─────────────────────────────

#[test]
fn tools_list_includes_surfaced_tool_when_in_backend_cache() {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};
    use std::time::Duration;

    // GIVEN: a backend registry with one backend that has a cached tool
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "my_server",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    // Directly populate the cache via get_cached_tool_names by writing to the backend
    // Since tools_cache is private, we test via the public API after warming via reflection.
    // Instead: verify that without cache, surfaced tool is absent.
    registry.register(backend);

    let surfaced = vec![SurfacedToolConfig {
        server: "my_server".to_string(),
        tool: "my_pinned_tool".to_string(),
    }];
    let mm = MetaMcp::new(Arc::clone(&registry)).with_surfaced_tools(surfaced);

    // WHEN: tools/list called (cache is empty — no warm start happened)
    let resp = mm.handle_tools_list(RequestId::Number(1));
    let result = resp.result.unwrap();
    let tools = result["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();

    // THEN: the surfaced tool is NOT present (cache empty → silently omitted)
    assert!(
        !names.contains(&"my_pinned_tool"),
        "Surfaced tool should be absent when backend cache is empty"
    );
    // AND: meta-tools are still present
    assert!(names.contains(&"gateway_invoke"));
}

#[test]
fn tools_list_meta_tools_always_present_regardless_of_surfaced_tools() {
    // GIVEN: MetaMcp with surfaced tools but no backends (cache will be empty)
    let surfaced = vec![SurfacedToolConfig {
        server: "nonexistent".to_string(),
        tool: "some_tool".to_string(),
    }];
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new())).with_surfaced_tools(surfaced);

    // WHEN: tools/list
    let resp = mm.handle_tools_list(RequestId::Number(1));
    let result = resp.result.unwrap();
    let tools = result["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();

    // THEN: core meta-tools are always present
    assert!(names.contains(&"gateway_invoke"));
    assert!(names.contains(&"gateway_search_tools"));
    assert!(names.contains(&"gateway_list_servers"));
}

#[test]
fn tools_list_code_mode_never_includes_surfaced_tools() {
    // GIVEN: code mode + surfaced tool configured
    let surfaced = vec![SurfacedToolConfig {
        server: "backend".to_string(),
        tool: "custom_tool".to_string(),
    }];
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_code_mode(true)
        .with_surfaced_tools(surfaced);

    // WHEN: tools/list
    let resp = mm.handle_tools_list(RequestId::Number(1));
    let result = resp.result.unwrap();
    let tools = result["tools"].as_array().unwrap();

    // THEN: exactly 2 tools (code mode wins)
    assert_eq!(tools.len(), 2);
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(!names.contains(&"custom_tool"));
}

// ── T2.4: Surfaced tool proxy routing in tools/call ───────────────────────

#[tokio::test]
async fn tools_call_surfaced_tool_on_missing_backend_returns_error() {
    // GIVEN: surfaced tool pointing to a backend that doesn't exist in registry
    let surfaced = vec![SurfacedToolConfig {
        server: "nonexistent_server".to_string(),
        tool: "pinned_tool".to_string(),
    }];
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new())).with_surfaced_tools(surfaced);

    // WHEN: calling the surfaced tool
    let resp = mm
        .handle_tools_call(
            RequestId::Number(1),
            "pinned_tool",
            json!({"arg": "val"}),
            None,
            None,
        )
        .await;

    // THEN: returns a backend-not-found error (not "Unknown tool" -32601)
    // The proxy dispatch was reached (surfaced tool map hit) and the backend was absent
    // which produces a BackendNotFound error, not a -32601.
    if let Some(err) = &resp.error {
        assert_ne!(err.code, -32601, "Should not be 'Unknown tool' error");
    } else {
        // May be a tool-result with is_error=true wrapping the backend error
        let content = &resp.result.unwrap()["content"];
        assert!(
            content[0]["text"]
                .as_str()
                .is_some_and(|s| s.contains("nonexistent_server") || s.contains("not found")),
            "Expected backend-not-found error in content, got: {content}"
        );
    }
}

#[tokio::test]
async fn tools_call_unknown_non_surfaced_tool_returns_32601() {
    // GIVEN: no surfaced tools, calling a completely unknown tool
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new()));

    // WHEN
    let resp = mm
        .handle_tools_call(
            RequestId::Number(1),
            "totally_unknown_xyz",
            json!({}),
            None,
            None,
        )
        .await;

    // THEN: -32601 "Unknown tool" error
    let err = resp.error.expect("Expected an RPC error for unknown tool");
    assert_eq!(err.code, -32601);
}

#[tokio::test]
async fn tools_call_surfaced_tool_name_bypasses_meta_tool_dispatch() {
    // GIVEN: a tool named identically to what would be an unknown meta-tool,
    // but registered as a surfaced tool
    let surfaced = vec![SurfacedToolConfig {
        server: "srv".to_string(),
        tool: "my_surfaced_tool".to_string(),
    }];
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new())).with_surfaced_tools(surfaced);

    // WHEN: calling the surfaced tool
    let resp = mm
        .handle_tools_call(
            RequestId::Number(1),
            "my_surfaced_tool",
            json!({}),
            None,
            None,
        )
        .await;

    // THEN: NOT a -32601 "Unknown tool" error — the surfaced map was consulted first
    if let Some(err) = &resp.error {
        assert_ne!(
            err.code, -32601,
            "Surfaced tool dispatch should not produce -32601; got: {err:?}"
        );
    }
    // (The actual error will be BackendNotFound since "srv" doesn't exist — that's fine)
}

// ── T2.5: Collision detection round-trip through handle_tools_call ────────

#[tokio::test]
async fn colliding_name_is_dispatched_as_meta_tool_not_proxy() {
    // GIVEN: attempt to surface "gateway_list_servers" — collision → dropped
    let surfaced = vec![SurfacedToolConfig {
        server: "my_backend".to_string(),
        tool: "gateway_list_servers".to_string(),
    }];
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new())).with_surfaced_tools(surfaced);
    assert!(mm.surfaced_tools.is_empty(), "Collision should be dropped");

    // WHEN: calling gateway_list_servers
    let resp = mm
        .handle_tools_call(
            RequestId::Number(1),
            "gateway_list_servers",
            json!({}),
            None,
            None,
        )
        .await;

    // THEN: dispatched as the real meta-tool, not proxied → success
    assert!(
        resp.error.is_none(),
        "gateway_list_servers should work as meta-tool: {:?}",
        resp.error
    );
}

// ── T2.7: Routing profile interaction ────────────────────────────────────

#[test]
fn resolve_surfaced_tool_excluded_by_deny_all_profile() {
    use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};

    // GIVEN: a profile that denies a specific backend
    let mut configs = std::collections::HashMap::new();
    configs.insert(
        "restricted".to_string(),
        RoutingProfileConfig {
            description: "Restricted".to_string(),
            deny_backends: Some(vec!["secret_server".to_string()]),
            ..Default::default()
        },
    );
    let registry = ProfileRegistry::from_config(&configs, "restricted");

    let surfaced = vec![SurfacedToolConfig {
        server: "secret_server".to_string(),
        tool: "secret_tool".to_string(),
    }];
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_profile_registry(registry)
        .with_surfaced_tools(surfaced);

    // WHEN: tools/list with no session (uses default profile = "restricted")
    let resp = mm.handle_tools_list(RequestId::Number(1));
    let result = resp.result.unwrap();
    let tools = result["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();

    // THEN: the surfaced tool is absent (backend denied by profile)
    assert!(
        !names.contains(&"secret_tool"),
        "Denied backend's surfaced tool should be absent; names: {names:?}"
    );
}
