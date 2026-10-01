// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Effect classification of every meta tool, as data (MIK-7216.IDEM.1).
//!
//! One table names each meta tool the gateway can expose and whether a call
//! to it is read-only or side-effecting. Admission reads the table to decide
//! whether a retry may re-execute. A name absent from the table is
//! side-effecting: the declared default, never an absence of classification.

/// Whether a call changes anything outside the gateway's response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Effect {
    /// Discovery or reporting; repeating the call cannot change state.
    ReadOnly,
    /// Executes external work or mutates gateway state.
    SideEffecting,
}

/// Every meta tool, with its effect. Backend annotations and operator target
/// strings cannot add a built-in here.
pub(crate) const META_TOOL_EFFECTS: &[(&str, Effect)] = &[
    ("gateway_search", Effect::ReadOnly),
    ("gateway_execute", Effect::SideEffecting),
    ("gateway_list_servers", Effect::ReadOnly),
    ("gateway_list_tools", Effect::ReadOnly),
    ("gateway_search_tools", Effect::ReadOnly),
    ("gateway_invoke", Effect::SideEffecting),
    ("gateway_get_stats", Effect::ReadOnly),
    ("gateway_cost_report", Effect::ReadOnly),
    ("gateway_webhook_status", Effect::ReadOnly),
    ("gateway_run_playbook", Effect::SideEffecting),
    ("gateway_kill_server", Effect::SideEffecting),
    ("gateway_revive_server", Effect::SideEffecting),
    ("gateway_list_disabled_capabilities", Effect::ReadOnly),
    ("gateway_set_profile", Effect::SideEffecting),
    ("gateway_get_profile", Effect::ReadOnly),
    ("gateway_list_profiles", Effect::ReadOnly),
    ("gateway_set_state", Effect::SideEffecting),
    ("gateway_reload_config", Effect::SideEffecting),
    ("gateway_reload_capabilities", Effect::SideEffecting),
];

/// The effect of a meta tool; a name not in the table is side-effecting.
pub(crate) fn meta_tool_effect(name: &str) -> Effect {
    META_TOOL_EFFECTS
        .iter()
        .find(|(n, _)| *n == name)
        .map_or(Effect::SideEffecting, |(_, e)| *e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::meta_mcp_tool_defs::{
        MetaToolGates, ToolTotal, build_code_mode_tools, build_meta_tools,
    };
    use std::collections::BTreeSet;

    /// Independent source: the tool definitions `tools/list` is built from,
    /// with every gate on, plus the Code Mode pair.
    fn listed_names() -> BTreeSet<String> {
        let gates = MetaToolGates {
            stats: true,
            reload: true,
            cost_report: true,
            webhook_status: true,
            playbooks: true,
            profiles: true,
        };
        build_meta_tools(gates, ToolTotal::Exact(1), 1)
            .into_iter()
            .chain(build_code_mode_tools())
            .map(|t| t.name)
            .collect()
    }

    #[test]
    fn effects_table_names_exactly_the_meta_tools_the_gateway_lists() {
        let table: BTreeSet<String> = META_TOOL_EFFECTS
            .iter()
            .map(|(n, _)| (*n).to_string())
            .collect();
        assert_eq!(table.len(), META_TOOL_EFFECTS.len(), "duplicate table key");
        assert_eq!(table, listed_names());
    }

    #[test]
    fn effects_table_pins_the_ten_read_only_meta_tools() {
        let read_only: BTreeSet<&str> = META_TOOL_EFFECTS
            .iter()
            .filter(|(_, e)| *e == Effect::ReadOnly)
            .map(|(n, _)| *n)
            .collect();
        let expected: BTreeSet<&str> = [
            "gateway_search",
            "gateway_list_servers",
            "gateway_list_tools",
            "gateway_search_tools",
            "gateway_get_stats",
            "gateway_cost_report",
            "gateway_webhook_status",
            "gateway_list_disabled_capabilities",
            "gateway_get_profile",
            "gateway_list_profiles",
        ]
        .into_iter()
        .collect();
        assert_eq!(read_only, expected);
    }

    #[test]
    fn a_name_absent_from_the_table_is_side_effecting() {
        assert_eq!(
            meta_tool_effect("gateway_not_a_tool"),
            Effect::SideEffecting
        );
        assert_eq!(meta_tool_effect("gateway_search"), Effect::ReadOnly);
    }
}
