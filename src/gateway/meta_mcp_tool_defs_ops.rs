// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::{
    Tool, destructive_idempotent_annotations, json, read_only_annotations,
    write_idempotent_annotations,
};

/// Build the `gateway_kill_server` meta-tool definition.
pub(crate) fn build_kill_server_tool() -> Tool {
    Tool {
        name: "gateway_kill_server".to_string(),
        title: Some("Kill Server".to_string()),
        description: Some(
            "Immediately disable routing to a backend server (operator kill switch). \
         The server's tools remain visible in search/list but are marked as disabled."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "server": {
                    "type": "string",
                    "description": "Name of the backend server to disable"
                }
            },
            "required": ["server"]
        }),
        output_schema: None,
        annotations: Some(destructive_idempotent_annotations("Kill Server")),
        role: None,
        projection: None,
    }
}

/// Build the `gateway_revive_server` meta-tool definition.
pub(crate) fn build_revive_server_tool() -> Tool {
    Tool {
        name: "gateway_revive_server".to_string(),
        title: Some("Revive Server".to_string()),
        description: Some(
            "Re-enable routing to a previously disabled backend server. \
         Also resets the error budget so the server gets a clean slate."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "server": {
                    "type": "string",
                    "description": "Name of the backend server to re-enable"
                }
            },
            "required": ["server"]
        }),
        output_schema: None,
        annotations: Some(write_idempotent_annotations("Revive Server")),
        role: None,
        projection: None,
    }
}

/// Build the `gateway_set_profile` meta-tool definition.
pub(crate) fn build_set_profile_tool() -> Tool {
    Tool {
        name: "gateway_set_profile".to_string(),
        title: Some("Set Routing Profile".to_string()),
        description: Some(
            "Switch the active routing profile for this session. \
         A routing profile restricts which tools and backends are available."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "profile": {
                    "type": "string",
                    "description": "Name of the routing profile to activate (e.g. \"research\", \"coding\")"
                }
            },
            "required": ["profile"]
        }),
        output_schema: None,
        annotations: Some(write_idempotent_annotations("Set Routing Profile")),
        role: None,
        projection: None,
    }
}

/// Build the `gateway_get_profile` meta-tool definition.
pub(crate) fn build_get_profile_tool() -> Tool {
    Tool {
        name: "gateway_get_profile".to_string(),
        title: Some("Get Routing Profile".to_string()),
        description: Some(
            "Show the active routing profile's name and description; admins also see its allow/deny patterns."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
        output_schema: None,
        annotations: Some(read_only_annotations("Get Routing Profile")),
        role: None,
        projection: None,
    }
}

/// Build the `gateway_list_disabled_capabilities` meta-tool definition.
///
/// Surfaces the per-capability error budget state, allowing operators
/// and LLM agents to see which capabilities are temporarily suspended and when
/// they will auto-recover.
pub(crate) fn build_list_disabled_capabilities_tool() -> Tool {
    Tool {
        name: "gateway_list_disabled_capabilities".to_string(),
        title: Some("List Disabled Capabilities".to_string()),
        description: Some(
            "List capabilities that have been automatically disabled due to a high error rate. \
         Each entry shows the backend, capability name, and how long it has been suspended. \
         Disabled capabilities auto-recover after the configured cooldown period (default 5 min). \
         Use gateway_revive_server to manually re-enable an entire backend immediately."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
        output_schema: None,
        annotations: Some(read_only_annotations("List Disabled Capabilities")),
        role: None,
        projection: None,
    }
}

/// Build the `gateway_list_profiles` meta-tool definition.
pub(crate) fn build_list_profiles_tool() -> Tool {
    Tool {
        name: "gateway_list_profiles".to_string(),
        title: Some("List Tool Profiles".to_string()),
        description: Some(
            "List all available routing profiles with their descriptions. \
         Use gateway_set_profile to switch to a profile that narrows \
         the visible toolset to the current task (e.g. \"coding\", \"research\")."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
        output_schema: None,
        annotations: Some(read_only_annotations("List Tool Profiles")),
        role: None,
        projection: None,
    }
}

/// Build the `gateway_set_state` meta-tool definition.
///
/// Transitions the session's FSM workflow state.  Tools whose
/// `visible_in_states` list is non-empty are only shown when the session is
/// in a matching state.  Tools with an empty `visible_in_states` are always
/// visible regardless of state.
pub(crate) fn build_set_state_tool() -> Tool {
    Tool {
        name: "gateway_set_state".to_string(),
        title: Some("Set Workflow State".to_string()),
        description: Some(
            "Transition the session to a new workflow state. \
         Capabilities with a non-empty `visible_in_states` list will only appear in \
         tools/list when the session is in a matching state. \
         Tools without `visible_in_states` are always visible. \
         Returns the previous state, new state, and visible tool count."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "state": {
                    "type": "string",
                    "description": "Target workflow state name (e.g. \"checkout\", \"payment\", \"default\")"
                }
            },
            "required": ["state"]
        }),
        output_schema: None,
        annotations: Some(write_idempotent_annotations("Set Workflow State")),
        role: None,
        projection: None,
    }
}

/// Build the `gateway_reload_config` meta-tool definition.
pub(crate) fn build_reload_config_tool() -> Tool {
    Tool {
        name: "gateway_reload_config".to_string(),
        title: Some("Reload Config".to_string()),
        description: Some(
            "Trigger an immediate reload of config.yaml from disk without restarting the gateway. \
         Returns a summary plus explicit restart-required fields when some changes stay pending. \
         Server host/port changes require a restart and are reported but not applied."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
        output_schema: None,
        annotations: Some(write_idempotent_annotations("Reload Config")),
        role: None,
        projection: None,
    }
}

/// Build the `gateway_cost_report` meta-tool definition.
pub(crate) fn build_cost_report_tool() -> Tool {
    Tool {
        name: "gateway_cost_report".to_string(),
        title: Some("Cost Report".to_string()),
        description: Some(
            "Return current session and API-key spend. Includes total cost, call count, \
         and breakdown by backend and tool. \
         Per-key totals are shown for 24 h / 7 d / 30 d rolling windows. \
         A caller with no session gets its own spend under `caller`; it is kept in \
         memory and resets after 24 h with no spend."
                .to_string(),
        ),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Specific session ID to report on. Defaults to current session."
                },
                "include_all_sessions": {
                    "type": "boolean",
                    "description": "Return all active sessions (admin view). Default false.",
                    "default": false
                },
                "include_all_keys": {
                    "type": "boolean",
                    "description": "Return all API key accumulators (admin view). Default false.",
                    "default": false
                }
            },
            "required": []
        }),
        output_schema: None,
        annotations: Some(read_only_annotations("Cost Report")),
        role: None,
        projection: None,
    }
}
