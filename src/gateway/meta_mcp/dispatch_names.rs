// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the meta-tool dispatch decides from a tool's name alone: the refusal
//! for a name no meta-tool answers, and whether a result is one of the
//! discovery arms that inspected their own canonical value. Its own file to
//! keep `mod.rs` under the file-size ratchet.

use super::super::meta_mcp_helpers::did_you_mean;
use super::{MetaMcp, MetaMcpCallerContext};
use crate::Error;
use crate::gateway::router::CallerStanding;

impl MetaMcp {
    /// The refusal for a name no meta-tool answers, with a suggestion drawn
    /// only from the tools this caller may see.
    pub(super) fn no_such_meta_tool(
        &self,
        tool_name: &str,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Error {
        const META_TOOLS: &[&str] = &[
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
            "gateway_set_state",
            "gateway_reload_config",
            "gateway_reload_capabilities",
        ];
        // The candidate pool is the EXPOSED set, not the static list.
        // The early return above keeps a hidden tool's exact name from
        // being confirmed; a near miss of that name reached here and
        // the suggester, drawing from every meta-tool that exists,
        // would answer with the name the allow-list is hiding. Filtering
        // the pool removes the route -- there is no longer a spelling
        // that makes this branch name an unexposed tool -- rather than
        // wording the hint more carefully and leaving the route open.
        let exposed: Vec<&str> = META_TOOLS
            .iter()
            .copied()
            .filter(|name| self.meta_tool_exposure.is_exposed(name))
            // Nor a tool this caller's standing withholds (A3).
            .filter(|name| CallerStanding::from(caller.scope()).permits(name))
            .collect();
        let suggestion = did_you_mean(tool_name, &exposed, 3, 3);
        let msg = match suggestion {
            Some(hint) => format!("Unknown tool: {tool_name}. {hint}"),
            None => format!("Unknown tool: {tool_name}"),
        };
        Error::json_rpc(-32601, msg)
    }

    /// Whether a meta-tool result is one of the three discovery arms, which
    /// inspected their canonical value (`inspect_discovery_value`): its
    /// response is marked so no later pass scans the serialised copy
    /// (MIK-7407.RESPONSE.3). Asked after the meta-tool match only, never on
    /// the direct-name routes above it.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::unused_self))]
    pub(super) fn marks_discovery(&self, tool_name: &str, scanned: bool) -> bool {
        #[cfg(feature = "firewall")]
        let armed = self.firewall.is_some();
        #[cfg(not(feature = "firewall"))]
        let armed = false;
        armed
            && scanned
            && matches!(
                tool_name,
                "gateway_search" | "gateway_list_tools" | "gateway_search_tools"
            )
    }
}
