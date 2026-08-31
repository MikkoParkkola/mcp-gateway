// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for `meta_mcp_tool_defs` — extracted for LOC compliance.

use super::*;

// ── build_meta_tools ────────────────────────────────────────────────

#[test]
fn build_meta_tools_base_count_without_optional_features() {
    // GIVEN: no stats, webhooks, reload, or cost_report; 42 tools, 3 servers
    // WHEN: building meta tools
    // THEN: 4 base + 1 playbook + 2 kill/revive + 2 set/get profile + 1 disabled-caps
    //       + 1 list-profiles + 1 set-state + 1 reload-capabilities = 13
    let tools = build_meta_tools(false, false, false, false, 42, 3);
    assert_eq!(tools.len(), 13);
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"gateway_list_servers"));
    assert!(names.contains(&"gateway_invoke"));
    assert!(names.contains(&"gateway_run_playbook"));
    assert!(names.contains(&"gateway_kill_server"));
    assert!(names.contains(&"gateway_revive_server"));
    assert!(names.contains(&"gateway_list_profiles"));
    assert!(!names.contains(&"gateway_get_stats"));
    assert!(!names.contains(&"gateway_webhook_status"));
    assert!(!names.contains(&"gateway_reload_config"));
    assert!(!names.contains(&"gateway_cost_report"));
}

#[test]
fn build_meta_tools_with_stats_adds_stats_tool() {
    let tools = build_meta_tools(true, false, false, false, 0, 0);
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"gateway_get_stats"));
}

#[test]
fn build_meta_tools_with_webhooks_adds_webhook_tool() {
    let tools = build_meta_tools(false, true, false, false, 0, 0);
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"gateway_webhook_status"));
}

#[test]
fn build_meta_tools_with_reload_adds_reload_tool() {
    let tools = build_meta_tools(false, false, true, false, 0, 0);
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"gateway_reload_config"));
}

#[test]
fn build_meta_tools_with_cost_report_adds_cost_report_tool() {
    let tools = build_meta_tools(false, false, false, true, 0, 0);
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"gateway_cost_report"));
}

#[test]
fn build_meta_tools_all_enabled_has_17_tools() {
    // 4 base + 1 stats + 1 cost_report + 1 webhooks + 1 playbook + 2 kill/revive
    // + 2 set/get profile + 1 disabled-caps + 1 list-profiles + 1 reload-config
    // + 1 set-state + 1 reload-capabilities = 17
    let tools = build_meta_tools(true, true, true, true, 0, 0);
    assert_eq!(tools.len(), 17);
}

#[test]
fn build_base_tools_all_have_descriptions() {
    for tool in build_base_tools(10, 2) {
        assert!(
            tool.description.is_some(),
            "Tool {} missing description",
            tool.name
        );
    }
}

#[test]
fn build_base_tools_all_have_object_schema() {
    for tool in build_base_tools(10, 2) {
        assert_eq!(
            tool.input_schema["type"], "object",
            "Tool {} has non-object schema",
            tool.name
        );
    }
}

// ── T1.1 + T1.2 additions ───────────────────────────────────────────────

#[test]
fn base_tools_read_only_have_non_none_annotations() {
    // GIVEN: 5 tools, 2 servers
    // WHEN: building base tools
    // THEN: all 4 base tools have Some(annotations)
    let tools = build_base_tools(5, 2);
    for tool in &tools {
        assert!(
            tool.annotations.is_some(),
            "Tool {} has None annotations",
            tool.name
        );
    }
}

#[test]
fn base_tool_read_only_hints_match_spec() {
    // GIVEN: base tools built with 100 tools across 5 servers
    let tools = build_base_tools(100, 5);
    let by_name = |name: &str| tools.iter().find(|t| t.name == name).unwrap();

    // WHEN/THEN: search, list_tools, list_servers are read-only, idempotent, not open-world
    for name in &[
        "gateway_search_tools",
        "gateway_list_tools",
        "gateway_list_servers",
    ] {
        let ann = by_name(name).annotations.as_ref().unwrap();
        assert_eq!(ann.read_only_hint, Some(true), "{name}: read_only_hint");
        assert_eq!(
            ann.destructive_hint,
            Some(false),
            "{name}: destructive_hint"
        );
        assert_eq!(ann.idempotent_hint, Some(true), "{name}: idempotent_hint");
        assert_eq!(ann.open_world_hint, Some(false), "{name}: open_world_hint");
    }

    // WHEN/THEN: invoke is NOT read-only, IS open-world, NOT destructive, NOT idempotent
    let invoke_ann = by_name("gateway_invoke").annotations.as_ref().unwrap();
    assert_eq!(invoke_ann.read_only_hint, Some(false));
    assert_eq!(invoke_ann.open_world_hint, Some(true));
    assert_eq!(invoke_ann.destructive_hint, Some(false));
    assert_eq!(invoke_ann.idempotent_hint, Some(false));
}

#[test]
fn all_gateway_meta_tools_have_complete_annotations_with_titles() {
    let mut tools = build_meta_tools(true, true, true, true, 42, 3);
    tools.extend(build_code_mode_tools());

    for tool in tools {
        let annotations = tool
            .annotations
            .as_ref()
            .unwrap_or_else(|| panic!("{} missing annotations", tool.name));

        assert_eq!(
            annotations.title.as_ref(),
            tool.title.as_ref(),
            "{} annotation title must mirror tool title",
            tool.name
        );
        assert!(
            annotations.read_only_hint.is_some(),
            "{} missing readOnlyHint",
            tool.name
        );
        assert!(
            annotations.destructive_hint.is_some(),
            "{} missing destructiveHint",
            tool.name
        );
        assert!(
            annotations.idempotent_hint.is_some(),
            "{} missing idempotentHint",
            tool.name
        );
        assert!(
            annotations.open_world_hint.is_some(),
            "{} missing openWorldHint",
            tool.name
        );
    }
}

#[test]
fn search_tools_has_output_schema_with_matches_array() {
    // GIVEN: any counts
    // WHEN: building base tools
    // THEN: gateway_search_tools has an output_schema describing a matches array
    let tools = build_base_tools(0, 0);
    let search = tools
        .iter()
        .find(|t| t.name == "gateway_search_tools")
        .unwrap();
    let schema = search
        .output_schema
        .as_ref()
        .expect("output_schema must be Some");
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["properties"]["matches"]["type"], "array");
    let item_props = &schema["properties"]["matches"]["items"]["properties"];
    for field in &["server", "tool", "description", "score"] {
        assert!(item_props.get(field).is_some(), "missing field: {field}");
    }
}

#[test]
fn base_tool_descriptions_embed_dynamic_counts() {
    // GIVEN: 77 tools across 4 servers
    // WHEN: building base tools
    // THEN: descriptions for search/list/servers contain "77" and "4"
    let tools = build_base_tools(77, 4);
    let by_name = |name: &str| {
        tools
            .iter()
            .find(|t| t.name == name)
            .unwrap()
            .description
            .as_deref()
            .unwrap()
            .to_string()
    };

    let search_desc = by_name("gateway_search_tools");
    assert!(search_desc.contains("77"), "search desc missing tool count");
    assert!(
        search_desc.contains('4'),
        "search desc missing server count"
    );

    let list_desc = by_name("gateway_list_tools");
    assert!(list_desc.contains("77"), "list desc missing tool count");
    assert!(list_desc.contains('4'), "list desc missing server count");

    let servers_desc = by_name("gateway_list_servers");
    assert!(
        servers_desc.contains('4'),
        "servers desc missing server count"
    );
}

#[test]
fn build_kill_server_tool_requires_server_param() {
    let tool = build_kill_server_tool();
    assert_eq!(tool.name, "gateway_kill_server");
    assert_eq!(tool.input_schema["required"][0], "server");
}

#[test]
fn build_revive_server_tool_requires_server_param() {
    let tool = build_revive_server_tool();
    assert_eq!(tool.name, "gateway_revive_server");
    assert_eq!(tool.input_schema["required"][0], "server");
}

// ── Annotations on management meta-tools ────────────────────────────────

#[test]
fn stats_tool_has_read_only_annotations() {
    // GIVEN: stats tool definition
    // WHEN: inspecting annotations
    // THEN: readOnly=true, destructive=false, idempotent=true
    let ann = build_stats_tool()
        .annotations
        .expect("annotations must be Some");
    assert_eq!(ann.read_only_hint, Some(true));
    assert_eq!(ann.destructive_hint, Some(false));
    assert_eq!(ann.idempotent_hint, Some(true));
}

#[test]
fn cost_report_tool_has_read_only_annotations() {
    // GIVEN: cost_report tool definition
    // WHEN: inspecting annotations
    // THEN: readOnly=true, destructive=false, idempotent=true
    let ann = build_cost_report_tool()
        .annotations
        .expect("annotations must be Some");
    assert_eq!(ann.read_only_hint, Some(true));
    assert_eq!(ann.destructive_hint, Some(false));
    assert_eq!(ann.idempotent_hint, Some(true));
}

#[test]
fn kill_server_tool_has_destructive_idempotent_annotations() {
    // GIVEN: kill_server tool definition
    // WHEN: inspecting annotations
    // THEN: readOnly=false, destructive=true, idempotent=true (kill is idempotent — calling twice is safe)
    let ann = build_kill_server_tool()
        .annotations
        .expect("annotations must be Some");
    assert_eq!(ann.read_only_hint, Some(false));
    assert_eq!(ann.destructive_hint, Some(true));
    assert_eq!(ann.idempotent_hint, Some(true));
    assert_eq!(ann.open_world_hint, Some(false));
}

#[test]
fn revive_server_tool_has_write_idempotent_annotations() {
    // GIVEN: revive_server tool definition
    // WHEN: inspecting annotations
    // THEN: readOnly=false, destructive=false, idempotent=true
    let ann = build_revive_server_tool()
        .annotations
        .expect("annotations must be Some");
    assert_eq!(ann.read_only_hint, Some(false));
    assert_eq!(ann.destructive_hint, Some(false));
    assert_eq!(ann.idempotent_hint, Some(true));
    assert_eq!(ann.open_world_hint, Some(false));
}

#[test]
fn reload_config_tool_has_write_idempotent_annotations() {
    // GIVEN: reload_config tool definition
    // WHEN: inspecting annotations
    // THEN: readOnly=false, destructive=false, idempotent=true
    let ann = build_reload_config_tool()
        .annotations
        .expect("annotations must be Some");
    assert_eq!(ann.read_only_hint, Some(false));
    assert_eq!(ann.destructive_hint, Some(false));
    assert_eq!(ann.idempotent_hint, Some(true));
}

// ── Code Mode tool definitions ──────────────────────────────────────────

#[test]
fn build_code_mode_tools_returns_exactly_two_tools() {
    let tools = build_code_mode_tools();
    assert_eq!(tools.len(), 2);
}

#[test]
fn build_code_mode_tools_are_gateway_search_and_execute() {
    let tools = build_code_mode_tools();
    assert_eq!(tools[0].name, "gateway_search");
    assert_eq!(tools[1].name, "gateway_execute");
}

#[test]
fn build_code_mode_search_tool_has_required_query_param() {
    let tool = build_code_mode_search_tool();
    assert_eq!(tool.input_schema["properties"]["query"]["type"], "string");
    assert_eq!(tool.input_schema["required"][0], "query");
}

#[test]
fn build_code_mode_search_tool_has_limit_and_schema_params() {
    let tool = build_code_mode_search_tool();
    assert_eq!(tool.input_schema["properties"]["limit"]["type"], "integer");
    assert_eq!(
        tool.input_schema["properties"]["include_schema"]["type"],
        "boolean"
    );
}

#[test]
fn build_code_mode_execute_tool_has_tool_chain_arguments_params() {
    let tool = build_code_mode_execute_tool();
    assert_eq!(tool.input_schema["properties"]["tool"]["type"], "string");
    assert_eq!(tool.input_schema["properties"]["chain"]["type"], "array");
    assert_eq!(
        tool.input_schema["properties"]["arguments"]["type"],
        "object"
    );
}

#[test]
fn all_code_mode_tools_have_descriptions() {
    for tool in build_code_mode_tools() {
        assert!(
            tool.description.as_deref().is_some_and(|d| !d.is_empty()),
            "Tool {} missing description",
            tool.name
        );
    }
}

// ── meta-tool exposure (GH issue 449) ───────────────────────────────

/// 449.EXPOSE.1 — an empty allow-list is "expose everything", so an existing
/// deployment that never sets the field keeps today's roster exactly.
#[test]
fn empty_allow_list_exposes_the_whole_roster() {
    let exposure = MetaToolExposure::from_names(&[]);
    let all = build_meta_tools(true, true, true, true, 42, 3);
    let filtered = build_meta_tools_filtered(true, true, true, true, 42, 3, &exposure);
    assert_eq!(
        filtered.len(),
        all.len(),
        "empty allow-list must not drop any meta-tool"
    );
}

/// 449.EXPOSE.2 — a non-empty allow-list yields only the named tools.
#[test]
fn allow_list_yields_only_the_named_tools() {
    let exposure = MetaToolExposure::from_names(&[
        "gateway_invoke".to_string(),
        "gateway_list_servers".to_string(),
    ]);
    let filtered = build_meta_tools_filtered(true, true, true, true, 42, 3, &exposure);
    let names: Vec<&str> = filtered.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["gateway_list_servers", "gateway_invoke"],
        "allow-list must yield exactly the named tools"
    );
}

/// 449.EXPOSE.3 — the predicate the list path uses is the same one the call
/// path consults, so it must answer for an omitted tool directly.
#[test]
fn predicate_hides_an_omitted_tool_and_keeps_a_named_one() {
    let exposure = MetaToolExposure::from_names(&["gateway_invoke".to_string()]);
    assert!(exposure.is_exposed("gateway_invoke"));
    assert!(
        !exposure.is_exposed("gateway_kill_server"),
        "a meta-tool absent from the allow-list must not be callable"
    );
}

/// 449.EXPOSE.4 — the allow-list governs only the tools it can list. Surfaced
/// backend tools and Code Mode's fixed surface must pass through untouched.
#[test]
fn predicate_does_not_govern_names_outside_the_builder_roster() {
    let exposure = MetaToolExposure::from_names(&["gateway_invoke".to_string()]);
    assert!(
        exposure.is_exposed("some_backend_tool"),
        "surfaced backend tools are not meta-tools"
    );
    assert!(
        exposure.is_exposed("gateway_execute"),
        "Code Mode's surface is out of scope for the meta-tool allow-list"
    );
}

/// 449.EXPOSE.5 — an unrecognised name is dropped with a warning, never fatal
/// (precedent: surfaced.rs:31-33). The recognised entries still apply.
#[test]
fn unrecognised_configured_name_is_dropped_not_fatal() {
    let exposure = MetaToolExposure::from_names(&[
        "gateway_invoke".to_string(),
        "gateway_typo_not_a_tool".to_string(),
    ]);
    assert!(exposure.is_exposed("gateway_invoke"));
    assert!(!exposure.is_exposed("gateway_kill_server"));
}

/// 449.EXPOSE.6 — the unfiltered builder keeps its existing six-argument form
/// and its existing output, so the call site in meta_mcp/mod.rs still compiles.
#[test]
fn unfiltered_builder_is_unchanged_by_the_exposure_work() {
    let tools = build_meta_tools(false, false, false, false, 42, 3);
    assert_eq!(tools.len(), 13);
}

/// 449.EXPOSE.7 — the config default exposes everything, so upgrading without
/// touching config.yaml changes nothing.
#[test]
fn config_default_exposes_every_meta_tool() {
    let config = crate::config::MetaMcpConfig::default();
    assert!(
        config.exposed_meta_tools.is_empty(),
        "default must be expose-all"
    );
    let exposure = MetaToolExposure::from_names(&config.exposed_meta_tools);
    assert!(exposure.is_exposed("gateway_kill_server"));
}

// ── P3 (test plan): the 19 compile-time meta-tool schemas meta-validate ────
//
// docs/design/2026-08-31-cluster-g-tool-schema-2020-12-validity-test-plan.md
// (MIK-6865.SCHEMA.1). Population and name set fixed by the design doc's
// "Implementer decisions — Increment 1" section: the 17 names from
// `build_meta_tools` with every optional flag true, plus the 2 disjoint
// Code Mode names — re-derived from source, not a hand-maintained literal
// list that could drift the moment a meta-tool is added.

const P3_EXPECTED_TOOL_NAMES: [&str; 19] = [
    "gateway_list_servers",
    "gateway_list_tools",
    "gateway_search_tools",
    "gateway_invoke",
    "gateway_get_stats",
    "gateway_run_playbook",
    "gateway_webhook_status",
    "gateway_kill_server",
    "gateway_revive_server",
    "gateway_set_profile",
    "gateway_get_profile",
    "gateway_list_disabled_capabilities",
    "gateway_list_profiles",
    "gateway_set_state",
    "gateway_reload_config",
    "gateway_cost_report",
    "gateway_reload_capabilities",
    "gateway_search",
    "gateway_execute",
];

fn p3_population() -> Vec<Tool> {
    let mut tools = build_meta_tools(true, true, true, true, 0, 0);
    tools.extend(build_code_mode_tools());
    tools
}

/// P3 — count and identity: a count alone passes if a definition is deleted
/// and another added, so the exact name set is asserted alongside the count.
#[test]
fn p3_population_is_exactly_the_19_named_gateway_tools() {
    let tools = p3_population();
    assert_eq!(tools.len(), 19, "expected exactly 19 gateway_* tool defs");

    let names: std::collections::HashSet<&str> =
        tools.iter().map(|t| t.name.as_str()).collect();
    let expected: std::collections::HashSet<&str> =
        P3_EXPECTED_TOOL_NAMES.into_iter().collect();
    assert_eq!(names, expected);
}

/// P3 — every `inputSchema` meta-validates against 2020-12, and every
/// `outputSchema` does too when present. Failure names the offending tool
/// and the validator's own error, so a regression says which schema broke
/// rather than "one of nineteen".
#[test]
fn p3_every_tool_schema_meta_validates_under_2020_12() {
    for tool in p3_population() {
        crate::capability::schema_validator::meta::validate_2020_12(&tool.input_schema)
            .unwrap_or_else(|error| {
                panic!("{}: inputSchema failed 2020-12 meta-validation: {error}", tool.name)
            });
        if let Some(output_schema) = &tool.output_schema {
            crate::capability::schema_validator::meta::validate_2020_12(output_schema)
                .unwrap_or_else(|error| {
                    panic!(
                        "{}: outputSchema failed 2020-12 meta-validation: {error}",
                        tool.name
                    )
                });
        }
    }
}
