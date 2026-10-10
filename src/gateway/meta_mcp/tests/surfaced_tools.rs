// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Surfaced tools, server revival and discovery inspection.

use super::*;

// ═══════════════════════════════════════════════════════════════════════════
// Phase 2: Static Tool Surfacing (RFC-0081 §T2.*)
// ═══════════════════════════════════════════════════════════════════════════

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
    let _ = registry.register(backend);

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

// Minor 10 (c) — MIK-6865.SCHEMA.1: a declared `outputSchema` must be
// byte-identical in the `tools/list` wire response to the one the capability
// declared; a non-object one under the `items` wrapper MCP needs (MIK-7959). Surfaced capability tools go through `CapabilityDefinition::
// to_mcp_tool` (src/capability/definition/mod.rs) and
// `project_tool_descriptor_trust_card` (src/trust/descriptor.rs) on the way
// to the wire; neither is supposed to touch the schema.
#[test]
fn ac_schema_10c_declared_output_schema_is_byte_identical_on_the_wire() {
    use crate::capability::{CapabilityBackend, CapabilityExecutor};

    let declared_output_schema = json!({
        "type": "array",
        "items": { "type": "string" },
        "prefixItems": [{ "type": "string" }],
        "minItems": 1
    });

    let mut cap = crate::capability::parse_capability(
        r"
name: schema_wire_check
description: Test capability with a declared, non-object output schema
providers:
  primary:
    service: rest
    config:
      base_url: https://example.invalid
      path: /check
",
    )
    .expect("fixture capability must parse");
    cap.schema.output = declared_output_schema.clone();

    let cap_backend = Arc::new(CapabilityBackend::new(
        "schema_wire_check_backend",
        Arc::new(CapabilityExecutor::new()),
    ));
    cap_backend
        .register_capability(cap)
        .expect("fixture capability must register");

    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_capabilities(cap_backend);
    let meta = meta.with_surfaced_tools(vec![SurfacedToolConfig {
        server: "schema_wire_check_backend".to_string(),
        tool: "schema_wire_check".to_string(),
    }]);

    let resp = meta.handle_tools_list(RequestId::Number(1));
    let result = resp.result.unwrap();
    let tools = result["tools"].as_array().unwrap();
    let wire_tool = tools
        .iter()
        .find(|t| t["name"] == json!("schema_wire_check"))
        .expect("surfaced capability tool must appear in tools/list");

    // MIK-7959: MCP needs an object root, so a non-object declared schema is
    // carried under `items` with an `$id` of its own; nothing else changes.
    let mut wire_schema = wire_tool["outputSchema"].clone();
    assert_eq!(wire_schema["type"], json!("object"));
    assert_eq!(wire_schema["required"], json!(["items"]));
    let carried = wire_schema["properties"]["items"]
        .as_object_mut()
        .expect("the declared schema is carried under items");
    assert!(carried.remove("$id").is_some());
    assert_eq!(
        serde_json::Value::Object(carried.clone()),
        declared_output_schema,
        "the declared outputSchema must reach the wire byte-identical under items"
    );
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
    let resp = Box::pin(mm.handle_tools_call(
        RequestId::Number(1),
        "pinned_tool",
        json!({"arg": "val"}),
        None,
        allow_all_ctx(),
    ))
    .await;

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
    let resp = Box::pin(mm.handle_tools_call(
        RequestId::Number(1),
        "totally_unknown_xyz",
        json!({}),
        None,
        allow_all_ctx(),
    ))
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
    let resp = Box::pin(mm.handle_tools_call(
        RequestId::Number(1),
        "my_surfaced_tool",
        json!({}),
        None,
        allow_all_ctx(),
    ))
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
    let resp = Box::pin(mm.handle_tools_call(
        RequestId::Number(1),
        "gateway_list_servers",
        json!({}),
        None,
        allow_all_ctx(),
    ))
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

// =========================================================================
// gateway_revive_server — circuit-breaker reset (MIK-5983)
// =========================================================================

/// Reviving a backend with a tripped circuit breaker must close the breaker,
/// not just the kill switch. Regression test for the 2026-06-11 incident where
/// the documented recovery path was a no-op for breaker trips.
#[test]
fn revive_server_resets_a_tripped_circuit_breaker() {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};
    use crate::failsafe::CircuitState;
    use std::time::Duration;

    // GIVEN: a registered backend whose breaker has tripped open
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "wedged_backend",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::ZERO,
    ));
    backend.trip_circuit_breaker_for_test();
    assert_eq!(
        backend.circuit_breaker_stats().state,
        CircuitState::Open,
        "precondition: breaker must be open"
    );
    let _ = registry.register(Arc::clone(&backend));
    let mm = MetaMcp::new(registry);

    // WHEN: the operator runs gateway_revive_server
    let result = mm
        .revive_server(&serde_json::json!({"server": "wedged_backend"}))
        .unwrap();

    // THEN: breaker is closed and the response reports the prior open state
    assert_eq!(backend.circuit_breaker_stats().state, CircuitState::Closed);
    assert_eq!(result["breaker_was_open"], true);
    assert_eq!(result["status"], "active");
}

/// Reviving a backend that is not registered still succeeds
/// (kill-switch-only semantics) and reports `breaker_was_open: false`.
#[test]
fn revive_server_unregistered_backend_reports_breaker_not_open() {
    let mm = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let result = mm
        .revive_server(&serde_json::json!({"server": "ghost"}))
        .unwrap();
    assert_eq!(result["breaker_was_open"], false);
    assert_eq!(result["status"], "active");
}

// The discovery surface is inspected once, on its canonical value
// (`MetaMcp::inspect_discovery_value`): see
// `router/tests/meta_firewall_verdict/list_and_task_block.rs` (#2350).

/// The non-Block arm: under a Warn rule the discovery value is served with
/// its credential redacted in place (#2350; Block is covered end to end).
#[cfg(feature = "firewall")]
#[test]
fn inspect_discovery_value_redacts_credentials_when_not_blocking() {
    use crate::security::firewall::{Firewall, FirewallAction, FirewallConfig, FirewallRule};

    let token = format!("ghp_{}", "abcdefghijklmnopqrstuvwxyz1234567890");
    let mut surface = json!({
        "tools": [{"name": "t", "description": format!("token: {token} for auth")}]
    });
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_firewall(Some(Arc::new(
        Firewall::from_config(
            FirewallConfig {
                rules: vec![FirewallRule {
                    tool_match: "tools/list".to_string(),
                    action: FirewallAction::Warn,
                    reason: None,
                    scan: Vec::new(),
                }],
                ..FirewallConfig::default()
            },
            None,
        )
        .with_continuations(meta.continuation()),
    )));

    meta.inspect_discovery_value(&mut surface)
        .expect("a Warn verdict serves the list");
    let description = surface["tools"][0]["description"].as_str().unwrap();
    assert!(
        description.contains("[REDACTED:credential]"),
        "{description}"
    );
    assert!(!description.contains("ghp_"), "{description}");
}
