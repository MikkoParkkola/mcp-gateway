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

/// One meta-tool the dispatch answers by name (MIK-8498 DISPATCH.3). The
/// meta match dispatches on this, so the names it routes are data: `ALL`
/// is checked against `surfaced::META_TOOLS` by a test, and a variant left
/// out of `ALL` is never built (`parse` reads only `ALL`), which the
/// dead-code lint refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MetaArm {
    Search,
    Execute,
    ListServers,
    ListTools,
    SearchTools,
    Invoke,
    GetStats,
    CostReport,
    WebhookStatus,
    RunPlaybook,
    KillServer,
    ReviveServer,
    ListDisabledCapabilities,
    SetProfile,
    GetProfile,
    ListProfiles,
    SetState,
    ReloadConfig,
    ReloadCapabilities,
}

impl MetaArm {
    /// Every meta-tool, in the order a did-you-mean hint ranks them.
    pub(super) const ALL: [Self; 19] = [
        Self::Search,
        Self::Execute,
        Self::ListServers,
        Self::ListTools,
        Self::SearchTools,
        Self::Invoke,
        Self::GetStats,
        Self::CostReport,
        Self::WebhookStatus,
        Self::RunPlaybook,
        Self::KillServer,
        Self::ReviveServer,
        Self::ListDisabledCapabilities,
        Self::SetProfile,
        Self::GetProfile,
        Self::ListProfiles,
        Self::SetState,
        Self::ReloadConfig,
        Self::ReloadCapabilities,
    ];

    /// The tool name a client calls this meta-tool by.
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Search => "gateway_search",
            Self::Execute => "gateway_execute",
            Self::ListServers => "gateway_list_servers",
            Self::ListTools => "gateway_list_tools",
            Self::SearchTools => "gateway_search_tools",
            Self::Invoke => "gateway_invoke",
            Self::GetStats => "gateway_get_stats",
            Self::CostReport => "gateway_cost_report",
            Self::WebhookStatus => "gateway_webhook_status",
            Self::RunPlaybook => "gateway_run_playbook",
            Self::KillServer => "gateway_kill_server",
            Self::ReviveServer => "gateway_revive_server",
            Self::ListDisabledCapabilities => "gateway_list_disabled_capabilities",
            Self::SetProfile => "gateway_set_profile",
            Self::GetProfile => "gateway_get_profile",
            Self::ListProfiles => "gateway_list_profiles",
            Self::SetState => "gateway_set_state",
            Self::ReloadConfig => "gateway_reload_config",
            Self::ReloadCapabilities => "gateway_reload_capabilities",
        }
    }

    /// The meta-tool `tool_name` names, or `None` for any other name.
    pub(super) fn parse(tool_name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|arm| arm.name() == tool_name)
    }
}

impl MetaMcp {
    /// The refusal for a name no meta-tool answers, with a suggestion drawn
    /// only from the tools this caller may see.
    pub(super) fn no_such_meta_tool(
        &self,
        tool_name: &str,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Error {
        // The candidate pool is the EXPOSED set, not the static list.
        // The early return above keeps a hidden tool's exact name from
        // being confirmed; a near miss of that name reached here and
        // the suggester, drawing from every meta-tool that exists,
        // would answer with the name the allow-list is hiding. Filtering
        // the pool removes the route -- there is no longer a spelling
        // that makes this branch name an unexposed tool -- rather than
        // wording the hint more carefully and leaving the route open.
        let exposed: Vec<&str> = MetaArm::ALL
            .iter()
            .map(|arm| arm.name())
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
