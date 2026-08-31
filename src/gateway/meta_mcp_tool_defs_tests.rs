// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for `meta_mcp_tool_defs` — extracted for LOC compliance.

use super::*;

// ── build_meta_tools: authorization-derived exposure (449.DERIVE.1-9) ──

use crate::gateway::router::ADMIN_META_TOOLS;

/// Names of the tools `build_meta_tools` produced for `surface`.
fn listed(surface: MetaToolSurface) -> Vec<String> {
    build_meta_tools(surface, 42, 3)
        .into_iter()
        .map(|tool| tool.name)
        .collect()
}

/// The surface of a gateway with no optional subsystem configured.
fn bare(is_admin: bool) -> MetaToolSurface {
    MetaToolSurface {
        is_admin,
        ..MetaToolSurface::default()
    }
}

#[test]
fn build_meta_tools_omits_every_admin_tool_from_a_standard_caller() {
    // GIVEN: every subsystem configured, but the caller does not hold admin
    // WHEN: building that caller's meta-tool list
    // THEN: no tool in ADMIN_META_TOOLS appears (449.DERIVE.1)
    let names = listed(MetaToolSurface {
        is_admin: false,
        ..MetaToolSurface::all()
    });
    for admin_tool in ADMIN_META_TOOLS {
        assert!(
            !names.iter().any(|name| name == admin_tool),
            "standard caller was offered admin tool {admin_tool}: {names:?}"
        );
    }
}

#[test]
fn build_meta_tools_admin_roster_is_unchanged_at_seventeen() {
    // GIVEN: an admin caller on a fully configured gateway
    // WHEN: building the meta-tool list
    // THEN: the roster is the same 17 tools as before authorization gating
    //       (449.DERIVE.2) — 4 base + stats + cost + webhook + playbook
    //       + kill + revive + 3 profile + disabled-caps + set-state
    //       + reload-config + reload-capabilities
    let names = listed(MetaToolSurface::all());
    assert_eq!(names.len(), 17, "{names:?}");
    for expected in [
        "gateway_list_servers",
        "gateway_invoke",
        "gateway_get_stats",
        "gateway_cost_report",
        "gateway_webhook_status",
        "gateway_run_playbook",
        "gateway_kill_server",
        "gateway_revive_server",
        "gateway_list_profiles",
        "gateway_reload_config",
    ] {
        assert!(names.iter().any(|name| name == expected), "{names:?}");
    }
}

#[test]
fn build_meta_tools_lists_playbook_tool_only_when_playbooks_configured() {
    // GIVEN: an admin caller, playbooks off then on
    // WHEN: building each list
    // THEN: gateway_run_playbook follows the flag (449.DERIVE.4)
    let without = listed(bare(true));
    assert!(!without.iter().any(|name| name == "gateway_run_playbook"));

    let with = listed(MetaToolSurface {
        playbooks: true,
        ..bare(true)
    });
    assert!(with.iter().any(|name| name == "gateway_run_playbook"));
}

#[test]
fn build_meta_tools_lists_profile_tools_only_when_profiles_configured() {
    // GIVEN: an admin caller, routing profiles off then on
    // WHEN: building each list
    // THEN: all three profile tools follow the flag together (449.DERIVE.5)
    const PROFILE_TOOLS: [&str; 3] = [
        "gateway_set_profile",
        "gateway_get_profile",
        "gateway_list_profiles",
    ];

    let without = listed(bare(true));
    for tool in PROFILE_TOOLS {
        assert!(!without.iter().any(|name| name == tool), "{without:?}");
    }

    let with = listed(MetaToolSurface {
        profiles: true,
        ..bare(true)
    });
    for tool in PROFILE_TOOLS {
        assert!(with.iter().any(|name| name == tool), "{with:?}");
    }
}

#[test]
fn build_meta_tools_lists_set_state_only_when_session_states_configured() {
    // GIVEN: an admin caller, state-gated capabilities off then on
    // WHEN: building each list
    // THEN: gateway_set_state follows the flag (449.DERIVE.6)
    let without = listed(bare(true));
    assert!(!without.iter().any(|name| name == "gateway_set_state"));

    let with = listed(MetaToolSurface {
        session_states: true,
        ..bare(true)
    });
    assert!(with.iter().any(|name| name == "gateway_set_state"));
}

#[test]
fn build_meta_tools_read_only_gateway_advertises_the_core_surface_only() {
    // GIVEN: a gateway with no optional subsystem and a non-admin caller
    // WHEN: building the meta-tool list
    // THEN: only the core surface is advertised (449.DERIVE.7)
    let mut names = listed(bare(false));
    names.sort();
    assert_eq!(
        names,
        vec![
            "gateway_invoke",
            "gateway_list_disabled_capabilities",
            "gateway_list_servers",
            "gateway_list_tools",
            "gateway_search_tools",
        ],
        "core surface drifted"
    );
}

#[test]
fn build_meta_tools_admin_only_difference_is_exactly_the_admin_constant() {
    // GIVEN: one fully configured gateway seen by an admin and a standard caller
    // WHEN: diffing the two listings
    // THEN: the difference is exactly ADMIN_META_TOOLS, so adding a name to that
    //       constant changes exposure with no second edit here (449.DERIVE.9)
    let admin = listed(MetaToolSurface::all());
    let standard = listed(MetaToolSurface {
        is_admin: false,
        ..MetaToolSurface::all()
    });

    let mut difference: Vec<&str> = admin
        .iter()
        .filter(|name| !standard.contains(name))
        .map(String::as_str)
        .collect();
    difference.sort_unstable();

    let mut expected: Vec<&str> = ADMIN_META_TOOLS.to_vec();
    expected.sort_unstable();

    assert_eq!(difference, expected);
}

#[test]
fn build_meta_tools_bare_admin_gateway_has_eight_tools() {
    // GIVEN: an admin caller and no optional subsystem configured
    // WHEN: building the meta-tool list
    // THEN: core surface + kill/revive + reload-capabilities = 8
    assert_eq!(listed(bare(true)).len(), 8);
}

#[test]
fn build_meta_tools_with_stats_adds_stats_tool() {
    let names = listed(MetaToolSurface {
        stats: true,
        ..bare(true)
    });
    assert!(names.iter().any(|name| name == "gateway_get_stats"));
}

#[test]
fn build_meta_tools_with_webhooks_adds_webhook_tool() {
    let names = listed(MetaToolSurface {
        webhooks: true,
        ..bare(true)
    });
    assert!(names.iter().any(|name| name == "gateway_webhook_status"));
}

#[test]
fn build_meta_tools_with_reload_adds_reload_tool() {
    let names = listed(MetaToolSurface {
        reload: true,
        ..bare(true)
    });
    assert!(names.iter().any(|name| name == "gateway_reload_config"));
}

#[test]
fn build_meta_tools_with_cost_report_adds_cost_report_tool() {
    let names = listed(MetaToolSurface {
        cost_report: true,
        ..bare(true)
    });
    assert!(names.iter().any(|name| name == "gateway_cost_report"));
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
    let mut tools = build_meta_tools(MetaToolSurface::all(), 42, 3);
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
